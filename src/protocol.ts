import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// x402 wire protocol.
//
// This file is the contract with every other x402 implementation, so it is
// deliberately a mirror of apps/web/src/lib/x402.ts. An agent that can pay
// FurlPay's own priced resources (e.g. GET /api/x402/fx) can pay ANY endpoint
// behind this gateway, byte for byte, with no client changes.
//
// The flow (scheme "exact"):
//
//   1. client  GET /resource
//   2. server  402 + { x402Version, accepts: [PaymentRequirements] }
//   3. client  signs an EIP-3009 `transferWithAuthorization` OFF-CHAIN
//   4. client  GET /resource  with  X-PAYMENT: base64(XPaymentPayload)
//   5. gateway verifies, hands the authorization to a facilitator, which
//              submits it on-chain and pays the gas
//   6. server  200 + X-PAYMENT-RESPONSE receipt
//
// Note step 3/5: the client NEVER submits a transaction itself and never pays
// gas, so there is no "transaction hash" to verify against an RPC. Anything
// that asks the payer for a tx hash is not x402 — it is a different (and much
// worse) protocol, because it forces the agent to hold native gas on every
// chain it might want to buy from.
// ---------------------------------------------------------------------------

export const X402_VERSION = 1;

/** Request header carrying the base64 payment payload. */
export const PAYMENT_HEADER = "x-payment";
/** Response header carrying the settlement receipt. */
export const RECEIPT_HEADER = "x-payment-response";

/** Web-layer hardening: cap the header before we spend cycles parsing it. */
export const MAX_HEADER_BYTES = 8192;

/** Default quote lifetime. Long enough for an agent to sign, short enough that
 *  a leaked quote is near-worthless. */
export const DEFAULT_QUOTE_TTL_SECONDS = 300;

/** How long a spent quote/nonce claim is retained. Must outlive any EIP-3009
 *  validity window, or a late replay could re-claim a freed key. */
export const REPLAY_CLAIM_TTL_SECONDS = 86_400;

/** Canonical (native-issuance, not bridged) USDC per network. */
export const NETWORK_USDC: Record<string, string> = {
  arbitrum: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
  "arbitrum-sepolia": "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
  base: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  polygon: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
  solana: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
};

/** USDC is 6-decimal on every network above. */
export const USDC_DECIMALS = 6;

export interface PaymentRequirements {
  scheme: "exact";
  network: string;
  maxAmountRequired: string; // atomic units
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  extra: {
    name: string;
    version: string;
    quoteId: string;
    expiresAt: number; // unix seconds
    binding: string; // HMAC binding this quote to (method, resource, amount)
    /** Present only when the quote is bound to a request body (see bindingMac). */
    bodyHash?: string;
  };
}

export interface X402Challenge {
  x402Version: number;
  error: string;
  accepts: PaymentRequirements[];
}

export interface EIP3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

export interface XPaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  payload: {
    signature: string;
    authorization: EIP3009Authorization;
  };
  /** Echo of the quote the client is paying against. Never trusted on its own —
   *  every field is re-derived server-side and compared. */
  extra?: {
    quoteId?: string;
    binding?: string;
    expiresAt?: number;
    bodyHash?: string;
  };
}

/** Keep paid content and fresh quotes out of every shared/CDN cache. A 200 that
 *  a CDN caches is a paid resource served free to the next unpaid client. */
export const noStoreHeaders: Record<string, string> = {
  "Cache-Control": "no-store, private, max-age=0",
  Vary: "X-PAYMENT",
};

/**
 * Confirmation depth required before releasing a resource, scaled to value.
 *
 * A settlement that is submitted but later reorged leaves the seller unpaid but
 * the resource already delivered. Depth is the only defence, and it is only
 * worth paying for in proportion to what is at stake.
 */
export function requiredConfirmations(amountAtomic: string): number {
  let usd: number;
  try {
    usd = Number(BigInt(amountAtomic)) / 10 ** USDC_DECIMALS;
  } catch {
    return 12; // unparseable → demand the strongest gate
  }
  if (usd < 1) return 3;
  if (usd < 10) return 6;
  return 12;
}

/** USD price → atomic units, as a decimal string. */
export function atomicAmount(priceUsd: number, decimals: number = USDC_DECIMALS): string {
  if (!Number.isFinite(priceUsd) || priceUsd <= 0) {
    throw new RangeError(`price must be a positive finite number (got ${priceUsd})`);
  }
  return String(Math.round(priceUsd * 10 ** decimals));
}

export interface BindingInput {
  method: string;
  resource: string;
  amount: string; // atomic
  quoteId: string;
  expiresAt: number;
  /** sha256 of the raw request body, when the quote is body-bound. */
  bodyHash?: string;
}

/**
 * HMAC that binds a quote to exactly one (method, resource, amount) — and, when
 * a body is present, to exactly one body.
 *
 * This is what stops cross-resource substitution: a payment authorized for
 * `GET /weather/london` at $0.001 cannot be presented to unlock
 * `POST /inference/gpt-5` at $2.00, because the MAC over the cheap quote will
 * not validate against the expensive resource's server-side expectation.
 *
 * The no-body form is byte-identical to apps/web/src/lib/x402.ts so quotes are
 * interchangeable between this gateway and FurlPay's first-party resources. The
 * body-hash term is a strict superset, appended only when body binding is on.
 */
export function bindingMac(secret: string | Buffer, input: BindingInput): string {
  const base = `${input.method} ${input.resource} ${input.amount} ${input.quoteId} ${input.expiresAt}`;
  const message = input.bodyHash ? `${base} ${input.bodyHash}` : base;
  return crypto.createHmac("sha256", secret).update(message).digest("hex");
}

/** sha256 of a raw request body. */
export function hashBody(body: string | Buffer): string {
  return crypto.createHash("sha256").update(body).digest("hex");
}

/** Constant-time compare of two hex strings of equal length. */
export function timingSafeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export type DecodedPayment =
  | { ok: true; payload: XPaymentPayload }
  | { ok: false; error: string };

/** Strict parse of the X-PAYMENT header. Malformed input is a 400, never a
 *  silently-released resource. */
export function decodePaymentHeader(header: string | null | undefined): DecodedPayment {
  if (!header) return { ok: false, error: "X-PAYMENT header required" };
  if (header.length > MAX_HEADER_BYTES) return { ok: false, error: "X-PAYMENT too large" };

  let payload: XPaymentPayload;
  try {
    payload = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  } catch {
    return { ok: false, error: "X-PAYMENT is not valid base64 JSON" };
  }

  const auth = payload?.payload?.authorization;
  if (payload?.x402Version !== X402_VERSION) return { ok: false, error: "Unsupported x402 version" };
  if (!auth || typeof payload?.payload?.signature !== "string") {
    return { ok: false, error: "Malformed x402 payload" };
  }
  for (const field of ["from", "to", "value", "validAfter", "validBefore", "nonce"] as const) {
    if (typeof auth[field] !== "string" || auth[field].length === 0) {
      return { ok: false, error: `Malformed authorization (missing ${field})` };
    }
  }
  return { ok: true, payload };
}

export interface SettlementReceipt {
  payer: string;
  transaction: string;
  network: string;
  asset: string;
  amountAtomic: string;
  resource: string;
  confirmations?: number;
  settledAt: string;
}

/** Value for the X-PAYMENT-RESPONSE header — the client's proof it paid. */
export function encodeReceipt(receipt: SettlementReceipt): string {
  return Buffer.from(JSON.stringify(receipt), "utf8").toString("base64");
}

export function decodeReceipt(header: string): SettlementReceipt | null {
  try {
    return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

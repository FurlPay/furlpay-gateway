import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// x402 wire protocol — v1 AND v2.
//
// v2 shipped Dec 2025 and is not just a header rename. The shapes changed:
//
//   v1                                    v2
//   ─────────────────────────────────     ─────────────────────────────────
//   X-PAYMENT (request)                   PAYMENT-SIGNATURE (request)
//   X-PAYMENT-RESPONSE (response)         PAYMENT-RESPONSE (response)
//   402 data in the BODY                  402 data in PAYMENT-REQUIRED header
//   requirements.maxAmountRequired        requirements.amount
//   requirements.resource/description     top-level resource: ResourceInfo
//   payload.extra (quote echo)            payload.accepted (full requirements)
//
// Both are supported here, and the version is negotiated per request: we answer
// in whatever dialect the client spoke. A 402 advertises BOTH (v2 in the
// PAYMENT-REQUIRED header, v1 in the body), which is exactly what v2's move of
// payment data out of the body makes possible.
//
// The payment model is identical across versions and is the thing people get
// wrong: the client signs an EIP-3009 authorization OFF-CHAIN. It never submits
// a transaction and never holds gas. The facilitator submits and pays the gas.
// Any design that asks the payer for a transaction hash is not x402.
// ---------------------------------------------------------------------------

export type X402Version = 1 | 2;

/** Default dialect for freshly-minted quotes when the client hasn't spoken yet. */
export const LATEST_X402_VERSION: X402Version = 2;

// ── headers ───────────────────────────────────────────────────────────────
export const HEADER_V1_PAYMENT = "x-payment";
export const HEADER_V1_RECEIPT = "X-PAYMENT-RESPONSE";
export const HEADER_V2_PAYMENT = "payment-signature";
export const HEADER_V2_RECEIPT = "PAYMENT-RESPONSE";
export const HEADER_V2_REQUIRED = "PAYMENT-REQUIRED";

/** Web-layer hardening: cap the header before we spend cycles parsing it. */
export const MAX_HEADER_BYTES = 8192;

export const DEFAULT_QUOTE_TTL_SECONDS = 300;

/** Must outlive any EIP-3009 validity window, or a late replay could re-claim a
 *  freed key. */
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

export const USDC_DECIMALS = 6;

// ── shared ────────────────────────────────────────────────────────────────

export interface EIP3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

/** The quote fields we carry in `extra` — identical across v1 and v2, which is
 *  what lets one binding scheme serve both. */
export interface QuoteExtra {
  name: string;
  version: string;
  quoteId: string;
  expiresAt: number;
  binding: string;
  bodyHash?: string;
  [k: string]: unknown;
}

// ── v1 ────────────────────────────────────────────────────────────────────

export interface PaymentRequirementsV1 {
  scheme: "exact";
  network: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  outputSchema?: Record<string, unknown>;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  extra: QuoteExtra;
}

export interface PaymentRequiredV1 {
  x402Version: 1;
  error: string;
  accepts: PaymentRequirementsV1[];
}

export interface PaymentPayloadV1 {
  x402Version: 1;
  scheme: string;
  network: string;
  payload: { signature: string; authorization: EIP3009Authorization };
  extra?: Partial<QuoteExtra>;
}

// ── v2 ────────────────────────────────────────────────────────────────────

/** v2 hoists resource metadata out of each requirement. `tags` / `serviceName`
 *  / `iconUrl` are the protocol's native discovery fields — a facilitator can
 *  crawl these, which is why a proprietary discovery index is the wrong build. */
export interface ResourceInfo {
  url: string;
  description?: string;
  mimeType?: string;
  serviceName?: string;
  tags?: string[];
  iconUrl?: string;
}

export interface PaymentRequirementsV2 {
  scheme: "exact";
  network: string;
  asset: string;
  amount: string; // v1's maxAmountRequired
  payTo: string;
  maxTimeoutSeconds: number;
  extra: QuoteExtra;
}

export interface PaymentRequiredV2 {
  x402Version: 2;
  error?: string;
  resource: ResourceInfo;
  accepts: PaymentRequirementsV2[];
  extensions?: Record<string, unknown>;
}

export interface PaymentPayloadV2 {
  x402Version: 2;
  resource?: ResourceInfo;
  /** The client echoes the FULL requirements it is paying against. Still not
   *  trusted — every field is re-derived server-side and compared. */
  accepted: PaymentRequirementsV2;
  payload: { signature: string; authorization: EIP3009Authorization };
  extensions?: Record<string, unknown>;
}

// ── normalized view ───────────────────────────────────────────────────────

/** One internal shape both dialects collapse to, so the gate is written once. */
export interface NormalizedPayment {
  version: X402Version;
  scheme: string;
  network: string;
  signature: string;
  authorization: EIP3009Authorization;
  /** Quote echo — the lookup key, never an assertion. */
  quoteId?: string;
  binding?: string;
  expiresAt?: number;
  bodyHash?: string;
}

// ── cache hygiene ─────────────────────────────────────────────────────────

/** A paid 200 that a CDN caches is a paid resource served free to the next
 *  unpaid caller. `Vary` covers both dialects' request headers. */
export const noStoreHeaders: Record<string, string> = {
  "Cache-Control": "no-store, private, max-age=0",
  Vary: "X-PAYMENT, PAYMENT-SIGNATURE",
};

// ── value-scaled settlement depth ─────────────────────────────────────────

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

export function atomicAmount(priceUsd: number, decimals: number = USDC_DECIMALS): string {
  if (!Number.isFinite(priceUsd) || priceUsd <= 0) {
    throw new RangeError(`price must be a positive finite number (got ${priceUsd})`);
  }
  return String(Math.round(priceUsd * 10 ** decimals));
}

// ── binding ───────────────────────────────────────────────────────────────

export interface BindingInput {
  method: string;
  resource: string;
  amount: string;
  quoteId: string;
  expiresAt: number;
  bodyHash?: string;
}

/**
 * HMAC binding a quote to exactly one (method, resource, amount) — and, when a
 * body is present, exactly one body.
 *
 * Deliberately version-independent: the same MAC validates a v1 or a v2 payment,
 * because both dialects carry the quote in `extra`. It is also byte-identical to
 * apps/web/src/lib/x402.ts, so quotes stay interchangeable with FurlPay's
 * first-party resources.
 */
export function bindingMac(secret: string | Buffer, input: BindingInput): string {
  const base = `${input.method} ${input.resource} ${input.amount} ${input.quoteId} ${input.expiresAt}`;
  const message = input.bodyHash ? `${base} ${input.bodyHash}` : base;
  return crypto.createHmac("sha256", secret).update(message).digest("hex");
}

export function hashBody(body: string | Buffer): string {
  return crypto.createHash("sha256").update(body).digest("hex");
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ── codec ─────────────────────────────────────────────────────────────────

export function b64encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

export function b64decode<T>(value: string): T {
  return JSON.parse(Buffer.from(value, "base64").toString("utf8")) as T;
}

export type HeaderLookup = (name: string) => string | null;

/** Which dialect did the client speak? `null` when it presented no payment. */
export function detectVersion(get: HeaderLookup): X402Version | null {
  if (get(HEADER_V2_PAYMENT)) return 2;
  if (get(HEADER_V1_PAYMENT)) return 1;
  return null;
}

export type DecodedPayment =
  | { ok: true; payment: NormalizedPayment }
  | { ok: false; error: string };

function validAuthorization(auth: unknown): auth is EIP3009Authorization {
  if (!auth || typeof auth !== "object") return false;
  const a = auth as Record<string, unknown>;
  return (["from", "to", "value", "validAfter", "validBefore", "nonce"] as const).every(
    (f) => typeof a[f] === "string" && (a[f] as string).length > 0
  );
}

/**
 * Strict parse of whichever payment header is present, normalized to one shape.
 * Malformed input is an error, never a silently-released resource.
 */
export function decodePayment(get: HeaderLookup): DecodedPayment {
  const version = detectVersion(get);
  if (version === null) return { ok: false, error: "Payment required" };

  const raw = version === 2 ? get(HEADER_V2_PAYMENT)! : get(HEADER_V1_PAYMENT)!;
  if (raw.length > MAX_HEADER_BYTES) return { ok: false, error: "Payment header too large" };

  let parsed: unknown;
  try {
    parsed = b64decode(raw);
  } catch {
    return { ok: false, error: "Payment header is not valid base64 JSON" };
  }

  if (version === 2) {
    const p = parsed as PaymentPayloadV2;
    if (p?.x402Version !== 2) return { ok: false, error: "Unsupported x402 version" };
    if (!p.accepted || typeof p.accepted !== "object") {
      return { ok: false, error: "Malformed v2 payload (missing `accepted`)" };
    }
    if (typeof p.payload?.signature !== "string" || !validAuthorization(p.payload?.authorization)) {
      return { ok: false, error: "Malformed v2 payload (bad signature/authorization)" };
    }
    const extra = (p.accepted.extra ?? {}) as Partial<QuoteExtra>;
    return {
      ok: true,
      payment: {
        version: 2,
        scheme: p.accepted.scheme,
        network: p.accepted.network,
        signature: p.payload.signature,
        authorization: p.payload.authorization,
        quoteId: extra.quoteId,
        binding: extra.binding,
        expiresAt: extra.expiresAt,
        bodyHash: extra.bodyHash,
      },
    };
  }

  const p = parsed as PaymentPayloadV1;
  if (p?.x402Version !== 1) return { ok: false, error: "Unsupported x402 version" };
  if (typeof p.payload?.signature !== "string" || !validAuthorization(p.payload?.authorization)) {
    return { ok: false, error: "Malformed v1 payload (bad signature/authorization)" };
  }
  const extra = (p.extra ?? {}) as Partial<QuoteExtra>;
  return {
    ok: true,
    payment: {
      version: 1,
      scheme: p.scheme,
      network: p.network,
      signature: p.payload.signature,
      authorization: p.payload.authorization,
      quoteId: extra.quoteId,
      binding: extra.binding,
      expiresAt: extra.expiresAt,
      bodyHash: extra.bodyHash,
    },
  };
}

// ── receipts ──────────────────────────────────────────────────────────────

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

/** v1 receipt — FurlPay's own X-PAYMENT-RESPONSE shape. */
export function encodeReceiptV1(receipt: SettlementReceipt): string {
  return b64encode(receipt);
}

/** v2 receipt — the reference SDK's SettleResponse shape. */
export function encodeReceiptV2(receipt: SettlementReceipt): string {
  return b64encode({
    success: true,
    transaction: receipt.transaction,
    network: receipt.network,
    payer: receipt.payer,
    amount: receipt.amountAtomic,
  });
}

export function decodeReceipt(header: string): SettlementReceipt | null {
  try {
    return b64decode<SettlementReceipt>(header);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// URL normalisation
// ---------------------------------------------------------------------------

/**
 * Strip trailing slashes in linear time.
 *
 * Replaces `.replace(/\/+$/, "")`, which CodeQL flags as js/polynomial-redos
 * and which measurement confirms is genuinely quadratic: on a string of N
 * slashes not terminated by one, the engine retries the `\/+$` match from every
 * starting offset. Measured on Node 22 — 10k slashes 66ms, 20k 270ms, 40k
 * 1102ms. Quadratic, not catastrophic, but a 40KB string burning a second of
 * CPU is a real cost.
 *
 * The three call sites this replaces all pass operator configuration
 * (facilitator base URL, Upstash URL, proxy origin), not request data, so the
 * practical severity in THIS package is low and the HIGH rating is inflated.
 * It is fixed regardless: this is a library, a consumer can pass whatever they
 * like into `createProxy({ origin })` or `httpFacilitator(url)`, and a
 * zero-dependency package has no business shipping a quadratic primitive when
 * the linear form is three lines.
 *
 * Verified equivalent to the regex over 1000 randomised inputs; 200k
 * pathological chars complete in 0.06ms.
 */
export function stripTrailingSlashes(input: string): string {
  let end = input.length;
  // 47 === "/". charCodeAt avoids allocating a substring per iteration.
  while (end > 0 && input.charCodeAt(end - 1) === 47) end--;
  return end === input.length ? input : input.slice(0, end);
}

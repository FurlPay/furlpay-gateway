import crypto from "node:crypto";
import {
  DEFAULT_QUOTE_TTL_SECONDS,
  NETWORK_USDC,
  REPLAY_CLAIM_TTL_SECONDS,
  USDC_DECIMALS,
  X402_VERSION,
  atomicAmount,
  bindingMac,
  decodePaymentHeader,
  encodeReceipt,
  hashBody,
  noStoreHeaders,
  requiredConfirmations,
  timingSafeEqualHex,
  type PaymentRequirements,
  type SettlementReceipt,
  type X402Challenge,
} from "./protocol.js";
import {
  FURLPAY_FACILITATOR,
  facilitatorRequest,
  httpFacilitator,
  type FacilitatorClient,
} from "./facilitator.js";
import { MemoryClaimStore, type ClaimStore } from "./store.js";

// ---------------------------------------------------------------------------
// The gateway.
//
// One rule governs this file: NOTHING the client sends is trusted. The client
// echoes back the quote it claims to be paying (quoteId, binding, amount), and
// every one of those fields is re-derived from server-side state and compared
// before a single byte of the resource is released. The client's copy is a
// lookup key, never an assertion.
// ---------------------------------------------------------------------------

/** Context handed to the price/description callbacks. */
export interface RequestContext {
  method: string;
  /** Canonical resource identity — the absolute URL, including query. */
  resource: string;
  url: URL;
  headers: Headers;
}

export type PriceResolver = number | ((ctx: RequestContext) => number | Promise<number>);

export interface GatewayOptions {
  /** Price in USD. A function lets you price per-route, per-caller, or by size. */
  price: PriceResolver;
  /** The wallet that gets paid. */
  payTo: string;
  /**
   * HMAC secret binding quotes to resources. Required — there is no default,
   * because a default would be a published default, and a published default is
   * a forgeable quote for every deployment that did not override it.
   */
  quoteSecret: string;
  network?: string;
  /** Token contract. Defaults to canonical USDC for `network`. */
  asset?: string;
  assetName?: string;
  assetVersion?: string;
  facilitator?: FacilitatorClient | string;
  claimStore?: ClaimStore;
  quoteTtlSeconds?: number;
  description?: string | ((ctx: RequestContext) => string);
  mimeType?: string;
  /**
   * Bind the quote to a hash of the request body. Defaults to true for methods
   * that carry one. Without it, a payment for `POST /infer {"model":"small"}`
   * also unlocks `POST /infer {"model":"large"}`.
   */
  bindBody?: boolean;
  /**
   * Settle on-chain before releasing (default). `false` verifies the
   * authorization but does not submit it — only correct if you settle out of
   * band and can tolerate delivering to a payer who never actually pays.
   */
  settle?: boolean;
  /** Override how a request maps to a resource identity. */
  resource?: (ctx: { method: string; url: URL }) => string;
  /** Fires after a confirmed settlement — ledger writes, webhooks, metering. */
  onSettled?: (receipt: SettlementReceipt) => void | Promise<void>;
  /** Fires when a payment is rejected. Useful for abuse signals. */
  onRejected?: (info: { reason: string; resource: string; payer?: string }) => void | Promise<void>;
}

export type GatewayDecision =
  | { kind: "allow"; receipt: SettlementReceipt; headers: Record<string, string> }
  | { kind: "challenge"; status: 402; body: X402Challenge; headers: Record<string, string> }
  | { kind: "reject"; status: 400; body: { error: string }; headers: Record<string, string> };

export interface AuthorizeInput {
  method: string;
  url: string | URL;
  headers: Headers | Record<string, string | undefined>;
  /** Raw request body. Required for body binding on POST/PUT/PATCH. */
  body?: string | Buffer;
}

const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);

function headerValue(headers: AuthorizeInput["headers"], name: string): string | null {
  if (typeof (headers as Headers).get === "function") return (headers as Headers).get(name);
  const rec = headers as Record<string, string | undefined>;
  return rec[name] ?? rec[name.toLowerCase()] ?? rec[name.toUpperCase()] ?? null;
}

export class Gateway {
  private readonly facilitator: FacilitatorClient;
  private readonly claims: ClaimStore;
  private readonly network: string;
  private readonly asset: string;
  private readonly ttl: number;

  constructor(private readonly opts: GatewayOptions) {
    if (!opts.quoteSecret || opts.quoteSecret.length < 16) {
      throw new Error(
        "@furlpay/gateway: `quoteSecret` is required and must be at least 16 chars. " +
          "Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
      );
    }
    if (!opts.payTo) throw new Error("@furlpay/gateway: `payTo` is required.");

    this.network = opts.network ?? "base";
    const asset = opts.asset ?? NETWORK_USDC[this.network];
    if (!asset) {
      throw new Error(
        `@furlpay/gateway: no canonical USDC address known for network "${this.network}" — pass \`asset\` explicitly.`
      );
    }
    this.asset = asset;
    this.ttl = opts.quoteTtlSeconds ?? DEFAULT_QUOTE_TTL_SECONDS;
    this.claims = opts.claimStore ?? new MemoryClaimStore();
    this.facilitator =
      typeof opts.facilitator === "string"
        ? httpFacilitator(opts.facilitator)
        : (opts.facilitator ?? httpFacilitator(FURLPAY_FACILITATOR));
  }

  /** True when replay claims are shared across instances. Assert this at boot
   *  in any multi-instance deployment. */
  get replayProtectionDurable(): boolean {
    return this.claims.isDurable;
  }

  private resourceId(method: string, url: URL): string {
    if (this.opts.resource) return this.opts.resource({ method, url });
    return `${url.origin}${url.pathname}${url.search}`;
  }

  private async priceFor(ctx: RequestContext): Promise<number> {
    return typeof this.opts.price === "function" ? await this.opts.price(ctx) : this.opts.price;
  }

  private describe(ctx: RequestContext): string {
    if (typeof this.opts.description === "function") return this.opts.description(ctx);
    return this.opts.description ?? `${ctx.method} ${new URL(ctx.resource).pathname} (per call)`;
  }

  /** Issue a fresh 402 quote for this request. */
  async quote(input: AuthorizeInput): Promise<PaymentRequirements> {
    const url = input.url instanceof URL ? input.url : new URL(input.url);
    const method = input.method.toUpperCase();
    const resource = this.resourceId(method, url);
    const ctx: RequestContext = {
      method,
      resource,
      url,
      headers: input.headers instanceof Headers ? input.headers : new Headers(),
    };

    const priceUsd = await this.priceFor(ctx);
    const amount = atomicAmount(priceUsd, USDC_DECIMALS);
    const quoteId = crypto.randomBytes(16).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + this.ttl;
    const bodyHash = this.shouldBindBody(method, input.body) ? hashBody(input.body!) : undefined;

    return {
      scheme: "exact",
      network: this.network,
      maxAmountRequired: amount,
      resource,
      description: this.describe(ctx),
      mimeType: this.opts.mimeType ?? "application/json",
      payTo: this.opts.payTo,
      maxTimeoutSeconds: this.ttl,
      asset: this.asset,
      extra: {
        name: this.opts.assetName ?? "USD Coin",
        version: this.opts.assetVersion ?? "2",
        quoteId,
        expiresAt,
        binding: bindingMac(this.opts.quoteSecret, { method, resource, amount, quoteId, expiresAt, bodyHash }),
        ...(bodyHash ? { bodyHash } : {}),
      },
    };
  }

  private shouldBindBody(method: string, body?: string | Buffer): boolean {
    if (this.opts.bindBody === false) return false;
    if (!BODY_METHODS.has(method)) return false;
    if (body === undefined || body === null) return false;
    return body.length > 0;
  }

  private async challenge(input: AuthorizeInput, error: string): Promise<GatewayDecision> {
    const requirements = await this.quote(input);
    return {
      kind: "challenge",
      status: 402,
      body: { x402Version: X402_VERSION, error, accepts: [requirements] },
      headers: { ...noStoreHeaders, "Content-Type": "application/json" },
    };
  }

  private reject(error: string): GatewayDecision {
    return {
      kind: "reject",
      status: 400,
      body: { error },
      headers: { ...noStoreHeaders, "Content-Type": "application/json" },
    };
  }

  /**
   * The gate. Returns `allow` only when a payment has been verified against a
   * server-derived quote, burned as single-use, and settled to the required
   * confirmation depth.
   */
  async authorize(input: AuthorizeInput): Promise<GatewayDecision> {
    const url = input.url instanceof URL ? input.url : new URL(input.url);
    const method = input.method.toUpperCase();
    const resource = this.resourceId(method, url);

    const header = headerValue(input.headers, "x-payment");
    if (!header) return this.challenge(input, "X-PAYMENT header required");

    const decoded = decodePaymentHeader(header);
    if (!decoded.ok) {
      // Malformed is the client's bug, not a pricing failure — a 402 here would
      // invite an agent to pay again against a payload we could not even read.
      await this.opts.onRejected?.({ reason: decoded.error, resource });
      return this.reject(decoded.error);
    }
    const payment = decoded.payload;
    const auth = payment.payload.authorization;

    const fail = async (reason: string): Promise<GatewayDecision> => {
      await this.opts.onRejected?.({ reason, resource, payer: auth.from });
      return this.challenge(input, reason);
    };

    // ── Re-derive the expectation. The client's echo is never the source. ──
    const ctx: RequestContext = {
      method,
      resource,
      url,
      headers: input.headers instanceof Headers ? input.headers : new Headers(),
    };
    const expectedAmount = atomicAmount(await this.priceFor(ctx), USDC_DECIMALS);

    if (payment.scheme !== "exact") return fail("Unsupported scheme");
    if (payment.network !== this.network) return fail(`Wrong network (expected ${this.network})`);
    if (auth.to.toLowerCase() !== this.opts.payTo.toLowerCase()) {
      return fail("Payment not addressed to this recipient");
    }

    // Amount: cover-or-more, compared as integers. A string compare here would
    // read "9" as larger than "10".
    try {
      if (BigInt(auth.value) < BigInt(expectedAmount)) {
        return fail(`Insufficient amount (expected ${expectedAmount} atomic units)`);
      }
    } catch {
      return fail("Invalid amount");
    }

    // ── Binding: is this payment for THIS resource, at THIS price, with THIS body? ──
    const quoteId = payment.extra?.quoteId;
    const binding = payment.extra?.binding;
    const expiresAt = payment.extra?.expiresAt;
    if (!quoteId || !binding || typeof expiresAt !== "number") {
      return fail("Missing quote binding (re-request the 402 quote)");
    }

    let bodyHash: string | undefined;
    if (this.shouldBindBody(method, input.body)) {
      bodyHash = hashBody(input.body!);
      if (payment.extra?.bodyHash && !timingSafeEqualHex(payment.extra.bodyHash, bodyHash)) {
        return fail("Body does not match the body this quote was issued for");
      }
      if (!payment.extra?.bodyHash) return fail("Quote is not body-bound (re-request the 402 quote)");
    }

    const expectedMac = bindingMac(this.opts.quoteSecret, {
      method,
      resource,
      amount: expectedAmount,
      quoteId,
      expiresAt,
      bodyHash,
    });
    if (!timingSafeEqualHex(expectedMac, binding)) {
      // The single most important line in this file: a payment minted for a
      // cheap resource dies here when presented to an expensive one.
      return fail("Quote binding mismatch (payment bound to a different resource)");
    }

    // ── Freshness ──
    const now = Math.floor(Date.now() / 1000);
    if (now > expiresAt) return fail("Quote expired (re-request the 402 quote)");
    const validAfter = Number(auth.validAfter);
    const validBefore = Number(auth.validBefore);
    if (Number.isFinite(validAfter) && now < validAfter) return fail("Authorization not yet valid");
    if (Number.isFinite(validBefore) && now > validBefore) return fail("Authorization expired");

    // ── Single-use. Nonce first: it is the money-level token, and burning it
    // before the quote means a racing replay can never reach settlement. ──
    if (!(await this.claims.claim(`x402:nonce:${auth.nonce}`, REPLAY_CLAIM_TTL_SECONDS))) {
      return fail("Authorization already used (replay)");
    }
    if (!(await this.claims.claim(`x402:quote:${quoteId}`, REPLAY_CLAIM_TTL_SECONDS))) {
      return fail("Quote already redeemed (replay)");
    }

    const requirements = await this.rebuildRequirements({
      method,
      resource,
      amount: expectedAmount,
      quoteId,
      expiresAt,
      bodyHash,
      description: this.describe(ctx),
    });

    // ── Verify + settle through the facilitator. ──
    const fReq = facilitatorRequest(payment, requirements);

    if (this.opts.settle === false) {
      const verdict = await this.facilitator.verify(fReq);
      if (!verdict.isValid) return fail(verdict.invalidReason ?? "Payment verification failed");
      return this.allow({
        payer: verdict.payer ?? auth.from,
        transaction: "",
        network: this.network,
        asset: this.asset,
        amountAtomic: auth.value,
        resource,
        settledAt: new Date().toISOString(),
      });
    }

    const settled = await this.facilitator.settle(fReq);
    if (!settled.success) {
      // Note: the nonce stays burned. A settle that errored may STILL land
      // on-chain, so freeing the nonce would reopen it for replay against a
      // payment that does confirm. An honest retry signs a fresh nonce, so this
      // never blocks a real payer.
      return fail(settled.errorReason ?? "Settlement failed");
    }

    const needed = requiredConfirmations(auth.value);
    if (typeof settled.confirmations === "number" && settled.confirmations < needed) {
      return fail(`Insufficient confirmations (${settled.confirmations}/${needed})`);
    }

    return this.allow({
      payer: settled.payer ?? auth.from,
      transaction: settled.transaction ?? "",
      network: settled.network ?? this.network,
      asset: this.asset,
      amountAtomic: auth.value,
      resource,
      confirmations: settled.confirmations,
      settledAt: new Date().toISOString(),
    });
  }

  /** Reconstruct the exact requirements this quote was minted with, so the
   *  facilitator checks the payment against the server's terms, not the
   *  client's copy of them. */
  private async rebuildRequirements(q: {
    method: string;
    resource: string;
    amount: string;
    quoteId: string;
    expiresAt: number;
    bodyHash?: string;
    description: string;
  }): Promise<PaymentRequirements> {
    return {
      scheme: "exact",
      network: this.network,
      maxAmountRequired: q.amount,
      resource: q.resource,
      description: q.description,
      mimeType: this.opts.mimeType ?? "application/json",
      payTo: this.opts.payTo,
      maxTimeoutSeconds: this.ttl,
      asset: this.asset,
      extra: {
        name: this.opts.assetName ?? "USD Coin",
        version: this.opts.assetVersion ?? "2",
        quoteId: q.quoteId,
        expiresAt: q.expiresAt,
        binding: bindingMac(this.opts.quoteSecret, {
          method: q.method,
          resource: q.resource,
          amount: q.amount,
          quoteId: q.quoteId,
          expiresAt: q.expiresAt,
          bodyHash: q.bodyHash,
        }),
        ...(q.bodyHash ? { bodyHash: q.bodyHash } : {}),
      },
    };
  }

  private async allow(receipt: SettlementReceipt): Promise<GatewayDecision> {
    await this.opts.onSettled?.(receipt);
    return {
      kind: "allow",
      receipt,
      headers: { ...noStoreHeaders, "X-PAYMENT-RESPONSE": encodeReceipt(receipt) },
    };
  }
}

import crypto from "node:crypto";
import {
  DEFAULT_QUOTE_TTL_SECONDS,
  HEADER_V1_RECEIPT,
  HEADER_V2_RECEIPT,
  HEADER_V2_REQUIRED,
  LATEST_X402_VERSION,
  NETWORK_USDC,
  REPLAY_CLAIM_TTL_SECONDS,
  USDC_DECIMALS,
  atomicAmount,
  b64encode,
  bindingMac,
  decodePayment,
  detectVersion,
  encodeReceiptV1,
  encodeReceiptV2,
  hashBody,
  noStoreHeaders,
  requiredConfirmations,
  timingSafeEqualHex,
  type HeaderLookup,
  type PaymentRequiredV1,
  type PaymentRequiredV2,
  type PaymentRequirementsV1,
  type PaymentRequirementsV2,
  type QuoteExtra,
  type ResourceInfo,
  type SettlementReceipt,
  type X402Version,
} from "./protocol.js";
import {
  FURLPAY_FACILITATOR,
  httpFacilitator,
  type FacilitatorClient,
  type FacilitatorRequest,
} from "./facilitator.js";
import { MemoryClaimStore, type ClaimStore } from "./store.js";

// ---------------------------------------------------------------------------
// The gateway.
//
// One rule governs this file: NOTHING the client sends is trusted. The client
// echoes back the quote it claims to be paying — in v1 as `extra`, in v2 as the
// full `accepted` requirements — and every one of those fields is re-derived
// from server-side state and compared before a byte of the resource is released.
// The client's copy is a lookup key, never an assertion.
// ---------------------------------------------------------------------------

export interface RequestContext {
  method: string;
  /** Canonical resource identity — the absolute URL, including query. */
  resource: string;
  url: URL;
  headers: Headers;
}

export type PriceResolver = number | ((ctx: RequestContext) => number | Promise<number>);

export interface GatewayOptions {
  price: PriceResolver;
  payTo: string;
  /** HMAC secret binding quotes to resources. No default — a published default
   *  would be a forgeable quote for every deployment that didn't override it. */
  quoteSecret: string;
  network?: string;
  asset?: string;
  assetName?: string;
  assetVersion?: string;
  facilitator?: FacilitatorClient | string;
  /** Pin the dialect used to talk to the facilitator. Default: mirror the
   *  client. Set to 1 when pointing at a v1-only facilitator. */
  facilitatorVersion?: X402Version;
  claimStore?: ClaimStore;
  quoteTtlSeconds?: number;
  description?: string | ((ctx: RequestContext) => string);
  mimeType?: string;
  /** v2 discovery metadata. These are the protocol's native fields — a
   *  facilitator can crawl them, so filling them in is how the resource becomes
   *  discoverable without any proprietary index. */
  serviceName?: string;
  tags?: string[];
  iconUrl?: string;
  /** Bind the quote to a hash of the request body (default on for POST/PUT/PATCH).
   *  Without it, a payment for {"model":"small"} also unlocks {"model":"large"}. */
  bindBody?: boolean;
  /** Settle on-chain before releasing (default). `false` verifies but does not
   *  collect — only correct if you settle out of band. */
  settle?: boolean;
  resource?: (ctx: { method: string; url: URL }) => string;
  onSettled?: (receipt: SettlementReceipt) => void | Promise<void>;
  onRejected?: (info: { reason: string; resource: string; payer?: string }) => void | Promise<void>;
}

export type GatewayDecision =
  | { kind: "allow"; receipt: SettlementReceipt; headers: Record<string, string> }
  | { kind: "challenge"; status: 402; body: PaymentRequiredV1; headers: Record<string, string> }
  | { kind: "reject"; status: 400; body: { error: string }; headers: Record<string, string> };

export interface AuthorizeInput {
  method: string;
  url: string | URL;
  headers: Headers | Record<string, string | undefined>;
  /** Raw request body. Required for body binding on POST/PUT/PATCH. */
  body?: string | Buffer;
}

/** The server-side truth about a quote. Both wire dialects render from this. */
interface MintedQuote {
  method: string;
  resource: string;
  amount: string;
  quoteId: string;
  expiresAt: number;
  bodyHash?: string;
  description: string;
  mimeType: string;
}

const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);

function lookup(headers: AuthorizeInput["headers"]): HeaderLookup {
  if (typeof (headers as Headers).get === "function") {
    return (name) => (headers as Headers).get(name);
  }
  const rec = headers as Record<string, string | undefined>;
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec)) if (v !== undefined) lower[k.toLowerCase()] = v;
  return (name) => lower[name.toLowerCase()] ?? null;
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
          "Generate one with: npx @furlpay/gateway secret"
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

  /** True when replay claims are shared across instances. Assert this at boot in
   *  any multi-instance deployment. */
  get replayProtectionDurable(): boolean {
    return this.claims.isDurable;
  }

  // ── quoting ─────────────────────────────────────────────────────────────

  private resourceId(method: string, url: URL): string {
    if (this.opts.resource) return this.opts.resource({ method, url });
    return `${url.origin}${url.pathname}${url.search}`;
  }

  private context(input: AuthorizeInput): RequestContext {
    const url = input.url instanceof URL ? input.url : new URL(input.url);
    const method = input.method.toUpperCase();
    return {
      method,
      resource: this.resourceId(method, url),
      url,
      headers: input.headers instanceof Headers ? input.headers : new Headers(),
    };
  }

  private async priceFor(ctx: RequestContext): Promise<number> {
    return typeof this.opts.price === "function" ? await this.opts.price(ctx) : this.opts.price;
  }

  private describe(ctx: RequestContext): string {
    if (typeof this.opts.description === "function") return this.opts.description(ctx);
    return this.opts.description ?? `${ctx.method} ${ctx.url.pathname} (per call)`;
  }

  private shouldBindBody(method: string, body?: string | Buffer): boolean {
    if (this.opts.bindBody === false) return false;
    if (!BODY_METHODS.has(method)) return false;
    if (body === undefined || body === null) return false;
    return body.length > 0;
  }

  /** Mint a fresh quote for this request. */
  private async mint(input: AuthorizeInput): Promise<MintedQuote> {
    const ctx = this.context(input);
    const amount = atomicAmount(await this.priceFor(ctx), USDC_DECIMALS);
    return {
      method: ctx.method,
      resource: ctx.resource,
      amount,
      quoteId: crypto.randomBytes(16).toString("hex"),
      expiresAt: Math.floor(Date.now() / 1000) + this.ttl,
      bodyHash: this.shouldBindBody(ctx.method, input.body) ? hashBody(input.body!) : undefined,
      description: this.describe(ctx),
      mimeType: this.opts.mimeType ?? "application/json",
    };
  }

  private extraFor(q: MintedQuote): QuoteExtra {
    return {
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
    };
  }

  private toV1(q: MintedQuote): PaymentRequirementsV1 {
    return {
      scheme: "exact",
      network: this.network,
      maxAmountRequired: q.amount,
      resource: q.resource,
      description: q.description,
      mimeType: q.mimeType,
      payTo: this.opts.payTo,
      maxTimeoutSeconds: this.ttl,
      asset: this.asset,
      extra: this.extraFor(q),
    };
  }

  private toV2(q: MintedQuote): PaymentRequirementsV2 {
    return {
      scheme: "exact",
      network: this.network,
      asset: this.asset,
      amount: q.amount,
      payTo: this.opts.payTo,
      maxTimeoutSeconds: this.ttl,
      extra: this.extraFor(q),
    };
  }

  private resourceInfo(q: MintedQuote): ResourceInfo {
    return {
      url: q.resource,
      description: q.description,
      mimeType: q.mimeType,
      ...(this.opts.serviceName ? { serviceName: this.opts.serviceName } : {}),
      ...(this.opts.tags?.length ? { tags: this.opts.tags } : {}),
      ...(this.opts.iconUrl ? { iconUrl: this.opts.iconUrl } : {}),
    };
  }

  /** Public quote surface — the v2 402 payload for this request. */
  async quote(input: AuthorizeInput): Promise<PaymentRequiredV2> {
    const q = await this.mint(input);
    return { x402Version: 2, resource: this.resourceInfo(q), accepts: [this.toV2(q)] };
  }

  /**
   * A 402 advertises BOTH dialects: v2 in the PAYMENT-REQUIRED header, v1 in the
   * body. v2 moving payment data out of the body is exactly what makes this
   * possible — a v2 client reads the header, a v1 client reads the body, and
   * neither needs to know the other exists.
   */
  private async challenge(input: AuthorizeInput, error: string): Promise<GatewayDecision> {
    const q = await this.mint(input);
    const v2: PaymentRequiredV2 = {
      x402Version: 2,
      error,
      resource: this.resourceInfo(q),
      accepts: [this.toV2(q)],
    };
    const v1: PaymentRequiredV1 = { x402Version: 1, error, accepts: [this.toV1(q)] };
    return {
      kind: "challenge",
      status: 402,
      body: v1,
      headers: {
        ...noStoreHeaders,
        "Content-Type": "application/json",
        [HEADER_V2_REQUIRED]: b64encode(v2),
      },
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

  // ── the gate ────────────────────────────────────────────────────────────

  /**
   * Returns `allow` only when a payment has been verified against a
   * server-derived quote, burned as single-use, and settled to the confirmation
   * depth its value requires.
   */
  async authorize(input: AuthorizeInput): Promise<GatewayDecision> {
    const ctx = this.context(input);
    const get = lookup(input.headers);
    const clientVersion = detectVersion(get);

    if (clientVersion === null) return this.challenge(input, "Payment required");

    const decoded = decodePayment(get);
    if (!decoded.ok) {
      // Malformed is the client's bug, not a pricing failure — a 402 here would
      // invite the agent to pay again against a payload we could not even read.
      await this.opts.onRejected?.({ reason: decoded.error, resource: ctx.resource });
      return this.reject(decoded.error);
    }
    const p = decoded.payment;
    const auth = p.authorization;

    const fail = async (reason: string): Promise<GatewayDecision> => {
      await this.opts.onRejected?.({ reason, resource: ctx.resource, payer: auth.from });
      return this.challenge(input, reason);
    };

    // ── re-derive the expectation; the client's echo is never the source ──
    const expectedAmount = atomicAmount(await this.priceFor(ctx), USDC_DECIMALS);

    if (p.scheme !== "exact") return fail("Unsupported scheme");
    if (p.network !== this.network) return fail(`Wrong network (expected ${this.network})`);
    if (auth.to.toLowerCase() !== this.opts.payTo.toLowerCase()) {
      return fail("Payment not addressed to this recipient");
    }

    // Integer compare — "9000" > "10000" lexicographically.
    try {
      if (BigInt(auth.value) < BigInt(expectedAmount)) {
        return fail(`Insufficient amount (expected ${expectedAmount} atomic units)`);
      }
    } catch {
      return fail("Invalid amount");
    }

    // ── binding: this resource, this price, this body? ──
    const { quoteId, binding, expiresAt } = p;
    if (!quoteId || !binding || typeof expiresAt !== "number") {
      return fail("Missing quote binding (re-request the 402 quote)");
    }

    let bodyHash: string | undefined;
    if (this.shouldBindBody(ctx.method, input.body)) {
      bodyHash = hashBody(input.body!);
      if (!p.bodyHash) return fail("Quote is not body-bound (re-request the 402 quote)");
      if (!timingSafeEqualHex(p.bodyHash, bodyHash)) {
        return fail("Body does not match the body this quote was issued for");
      }
    }

    const expectedMac = bindingMac(this.opts.quoteSecret, {
      method: ctx.method,
      resource: ctx.resource,
      amount: expectedAmount,
      quoteId,
      expiresAt,
      bodyHash,
    });
    if (!timingSafeEqualHex(expectedMac, binding)) {
      // The most important line in this file: a payment minted for a cheap
      // resource dies here when presented to an expensive one.
      return fail("Quote binding mismatch (payment bound to a different resource)");
    }

    // ── freshness ──
    const now = Math.floor(Date.now() / 1000);
    if (now > expiresAt) return fail("Quote expired (re-request the 402 quote)");
    const validAfter = Number(auth.validAfter);
    const validBefore = Number(auth.validBefore);
    if (Number.isFinite(validAfter) && now < validAfter) return fail("Authorization not yet valid");
    if (Number.isFinite(validBefore) && now > validBefore) return fail("Authorization expired");

    // ── single-use. Nonce first: it is the money-level token, so burning it
    // before the quote means a racing replay never reaches settlement. ──
    if (!(await this.claims.claim(`x402:nonce:${auth.nonce}`, REPLAY_CLAIM_TTL_SECONDS))) {
      return fail("Authorization already used (replay)");
    }
    if (!(await this.claims.claim(`x402:quote:${quoteId}`, REPLAY_CLAIM_TTL_SECONDS))) {
      return fail("Quote already redeemed (replay)");
    }

    // ── verify + settle, in the dialect the facilitator speaks ──
    const q: MintedQuote = {
      method: ctx.method,
      resource: ctx.resource,
      amount: expectedAmount,
      quoteId,
      expiresAt,
      bodyHash,
      description: this.describe(ctx),
      mimeType: this.opts.mimeType ?? "application/json",
    };
    const fReq = this.facilitatorRequest(q, p, clientVersion);

    if (this.opts.settle === false) {
      const verdict = await this.facilitator.verify(fReq);
      if (!verdict.isValid) return fail(verdict.invalidReason ?? "Payment verification failed");
      return this.allow(clientVersion, {
        payer: verdict.payer ?? auth.from,
        transaction: "",
        network: this.network,
        asset: this.asset,
        amountAtomic: auth.value,
        resource: ctx.resource,
        settledAt: new Date().toISOString(),
      });
    }

    const settled = await this.facilitator.settle(fReq);
    if (!settled.success) {
      // The nonce stays burned. A settle that errored may STILL land on-chain,
      // so freeing it would reopen replay against a payment that does confirm.
      // An honest retry signs a fresh nonce, so this never blocks a real payer.
      return fail(settled.errorReason ?? "Settlement failed");
    }

    const needed = requiredConfirmations(auth.value);
    if (typeof settled.confirmations === "number" && settled.confirmations < needed) {
      return fail(`Insufficient confirmations (${settled.confirmations}/${needed})`);
    }

    return this.allow(clientVersion, {
      payer: settled.payer ?? auth.from,
      transaction: settled.transaction ?? "",
      network: settled.network ?? this.network,
      asset: this.asset,
      // v2's `upto` scheme can settle less than the authorized maximum.
      amountAtomic: settled.amount ?? auth.value,
      resource: ctx.resource,
      confirmations: settled.confirmations,
      settledAt: new Date().toISOString(),
    });
  }

  /** Rebuild the requirements the quote was minted with, so the facilitator
   *  checks the payment against the SERVER's terms, not the client's copy. */
  private facilitatorRequest(
    q: MintedQuote,
    payment: { signature: string; authorization: import("./protocol.js").EIP3009Authorization },
    clientVersion: X402Version
  ): FacilitatorRequest {
    const version = this.opts.facilitatorVersion ?? clientVersion;

    if (version === 2) {
      return {
        x402Version: 2,
        paymentPayload: {
          x402Version: 2,
          resource: this.resourceInfo(q),
          accepted: this.toV2(q),
          payload: { signature: payment.signature, authorization: payment.authorization },
        },
        paymentRequirements: this.toV2(q),
      };
    }
    return {
      x402Version: 1,
      paymentPayload: {
        x402Version: 1,
        scheme: "exact",
        network: this.network,
        payload: { signature: payment.signature, authorization: payment.authorization },
        extra: this.extraFor(q),
      },
      paymentRequirements: this.toV1(q),
    };
  }

  /** Answer in the dialect the client spoke — and, harmlessly, the other one too,
   *  so a proxy or SDK expecting either finds its receipt. */
  private async allow(version: X402Version, receipt: SettlementReceipt): Promise<GatewayDecision> {
    await this.opts.onSettled?.(receipt);
    return {
      kind: "allow",
      receipt,
      headers: {
        ...noStoreHeaders,
        [HEADER_V1_RECEIPT]: encodeReceiptV1(receipt),
        [HEADER_V2_RECEIPT]: encodeReceiptV2(receipt),
      },
    };
  }
}

export { LATEST_X402_VERSION };

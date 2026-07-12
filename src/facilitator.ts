import type {
  PaymentPayloadV1,
  PaymentPayloadV2,
  PaymentRequirementsV1,
  PaymentRequirementsV2,
} from "./protocol.js";

// ---------------------------------------------------------------------------
// Facilitator client.
//
// The facilitator is the only party that touches a chain: it verifies the
// EIP-3009 authorization, submits it, and pays the gas. Keeping it behind an
// interface is the whole point — the gateway needs no private key, no RPC
// endpoint and no gas balance, which is what makes it safe to self-host.
//
// Default: FurlPay's facilitator. Any x402-compliant facilitator works; point
// `baseUrl` at Coinbase's and settlement goes through Coinbase, unchanged.
// ---------------------------------------------------------------------------

export const FURLPAY_FACILITATOR = "https://furlpay.com/api/x402/facilitator";

/** The envelope is versioned: v1 and v2 carry different inner shapes. */
export type FacilitatorRequest =
  | { x402Version: 1; paymentPayload: PaymentPayloadV1; paymentRequirements: PaymentRequirementsV1 }
  | { x402Version: 2; paymentPayload: PaymentPayloadV2; paymentRequirements: PaymentRequirementsV2 };

export interface VerifyResult {
  isValid: boolean;
  payer?: string;
  invalidReason?: string;
  invalidMessage?: string;
}

export interface SettleResult {
  success: boolean;
  transaction?: string;
  network: string;
  payer?: string;
  errorReason?: string;
  errorMessage?: string;
  /** Actual amount settled. v2's `upto` scheme can settle LESS than the
   *  authorized maximum, so the receipt must report this, not the authorization. */
  amount?: string;
  confirmations?: number;
  requiredConfirmations?: number;
}

export interface SupportedKind {
  x402Version: number;
  scheme: string;
  network: string;
}

export interface FacilitatorClient {
  verify(req: FacilitatorRequest): Promise<VerifyResult>;
  settle(req: FacilitatorRequest): Promise<SettleResult>;
  supported(): Promise<SupportedKind[]>;
}

export interface HttpFacilitatorOptions {
  apiKey?: string;
  /** A hung facilitator must not hang the origin. */
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * HTTP facilitator client.
 *
 * Every failure path fails CLOSED: a timeout, a non-2xx, or an unparseable body
 * resolves to "not valid" / "not settled", never to a released resource. A
 * facilitator you cannot reach must cost you a sale, not the resource.
 */
export function httpFacilitator(
  baseUrl: string = FURLPAY_FACILITATOR,
  opts: HttpFacilitatorOptions = {}
): FacilitatorClient {
  const base = baseUrl.replace(/\/+$/, "");
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const doFetch = opts.fetchImpl ?? globalThis.fetch;

  if (typeof doFetch !== "function") {
    throw new Error("No fetch implementation available — pass `fetchImpl` (Node >=18 has a global fetch).");
  }

  async function post<T>(path: string, body: unknown, onError: (reason: string) => T): Promise<T> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await doFetch(`${base}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(opts.apiKey ? { Authorization: `Bearer ${opts.apiKey}` } : {}),
        },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      if (!res.ok) return onError(`facilitator_http_${res.status}`);
      return (await res.json()) as T;
    } catch (e) {
      const reason = (e as Error)?.name === "AbortError" ? "facilitator_timeout" : "facilitator_unreachable";
      return onError(reason);
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    verify(req) {
      return post<VerifyResult>("/verify", req, (invalidReason) => ({ isValid: false, invalidReason }));
    },
    settle(req) {
      const network =
        req.x402Version === 2 ? req.paymentRequirements.network : req.paymentRequirements.network;
      return post<SettleResult>("/settle", req, (errorReason) => ({ success: false, network, errorReason }));
    },
    async supported() {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      try {
        const res = await doFetch(`${base}/supported`, { signal: ctl.signal });
        if (!res.ok) return [];
        const body = (await res.json()) as { kinds?: SupportedKind[] } | SupportedKind[];
        return Array.isArray(body) ? body : (body.kinds ?? []);
      } catch {
        return [];
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

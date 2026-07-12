import { X402_VERSION, type PaymentRequirements, type XPaymentPayload } from "./protocol.js";

// ---------------------------------------------------------------------------
// Facilitator client.
//
// The facilitator is the only party that touches a chain: it verifies the
// EIP-3009 authorization, submits it, and pays the gas. Keeping it behind an
// interface is the whole point — the gateway never needs a private key, an RPC
// endpoint, or a gas balance, which is what makes it safe to self-host.
//
// Default: FurlPay's facilitator (Arbitrum, Base, Solana). Any x402-compliant
// facilitator works; point `baseUrl` at Coinbase's and this gateway settles
// through Coinbase instead, with no other change.
// ---------------------------------------------------------------------------

export const FURLPAY_FACILITATOR = "https://furlpay.com/api/x402/facilitator";

export interface FacilitatorRequest {
  x402Version: number;
  paymentPayload: XPaymentPayload;
  paymentRequirements: PaymentRequirements;
}

export interface VerifyResult {
  isValid: boolean;
  payer?: string;
  invalidReason?: string;
}

export interface SettleResult {
  success: boolean;
  transaction?: string;
  network: string;
  payer?: string;
  errorReason?: string;
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
  /** Sent as `Authorization: Bearer` — some facilitators meter their callers. */
  apiKey?: string;
  /** Per-request timeout. A hung facilitator must not hang the origin. */
  timeoutMs?: number;
  /** Injectable for tests and non-standard runtimes. */
  fetchImpl?: typeof fetch;
}

/**
 * HTTP facilitator client.
 *
 * Every failure path here fails CLOSED: a timeout, a non-2xx, or an unparseable
 * body resolves to "not valid" / "not settled", never to a released resource.
 * An unreachable facilitator must cost the seller a sale, not the resource.
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
      const network = req.paymentRequirements?.network ?? "unknown";
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

/** Build the request envelope a facilitator expects. */
export function facilitatorRequest(
  paymentPayload: XPaymentPayload,
  paymentRequirements: PaymentRequirements
): FacilitatorRequest {
  return { x402Version: X402_VERSION, paymentPayload, paymentRequirements };
}

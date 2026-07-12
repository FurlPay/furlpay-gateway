import { Gateway, type GatewayOptions } from "../gateway.js";
import type { SettlementReceipt } from "../protocol.js";

// ---------------------------------------------------------------------------
// Express / Connect adapter.
//
// Structurally typed against Express rather than importing it, so this package
// keeps its zero-runtime-dependency promise and works with Connect, Polka, and
// anything else with the same middleware shape.
// ---------------------------------------------------------------------------

interface ExpressLikeRequest {
  method: string;
  originalUrl?: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  protocol?: string;
  secure?: boolean;
  get?(name: string): string | undefined;
  /** Raw body bytes — see `captureRawBody`. */
  rawBody?: Buffer | string;
  /** Set by this middleware once payment is confirmed. */
  payment?: SettlementReceipt;
}

interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  set(field: string, value: string): ExpressLikeResponse;
  json(body: unknown): unknown;
}

type Next = (err?: unknown) => void;

/**
 * `express.json()` discards the raw bytes, but body binding needs to hash
 * exactly what the client sent — a re-serialized `req.body` is a different byte
 * string (key order, whitespace) and would hash differently every time.
 *
 * @example
 *   app.use(express.json({ verify: captureRawBody }));
 */
export function captureRawBody(req: ExpressLikeRequest, _res: unknown, buf: Buffer): void {
  req.rawBody = buf;
}

function absoluteUrl(req: ExpressLikeRequest): string {
  const headerHost = req.get?.("host") ?? (req.headers.host as string | undefined);
  const host = headerHost ?? "localhost";
  const proto = req.secure ? "https" : (req.protocol ?? "http");
  return `${proto}://${host}${req.originalUrl ?? req.url}`;
}

function flatHeaders(req: ExpressLikeRequest): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === "string") out[k.toLowerCase()] = v;
    else if (Array.isArray(v)) out[k.toLowerCase()] = v[0] ?? "";
  }
  return out;
}

const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);

/**
 * Express middleware that paywalls everything mounted after it.
 *
 * On success `req.payment` holds the settlement receipt, so the route handler
 * can meter, log, or attribute the call to the paying agent.
 *
 * @example
 *   app.get("/api/weather", expressPaywall({ ... }), (req, res) => {
 *     res.json({ tempC: 17, paidBy: req.payment.payer });
 *   });
 */
export function expressPaywall(opts: GatewayOptions) {
  const gateway = new Gateway(opts);
  const bindBody = opts.bindBody !== false;

  return async function middleware(
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: Next
  ): Promise<void> {
    try {
      const method = req.method.toUpperCase();

      // Fail closed rather than silently downgrade: if body binding is on and we
      // cannot see the raw bytes, a payment for one body would unlock any other.
      if (bindBody && BODY_METHODS.has(method) && req.rawBody === undefined) {
        res
          .status(500)
          .set("Cache-Control", "no-store")
          .json({
            error:
              "gateway_misconfigured: body binding is enabled but req.rawBody is unset. " +
              "Add `app.use(express.json({ verify: captureRawBody }))`, or pass `bindBody: false` " +
              "to accept that a payment for one body unlocks any other.",
          });
        return;
      }

      const decision = await gateway.authorize({
        method,
        url: absoluteUrl(req),
        headers: flatHeaders(req),
        body: req.rawBody,
      });

      if (decision.kind !== "allow") {
        for (const [k, v] of Object.entries(decision.headers)) res.set(k, v);
        res.status(decision.status).json(decision.body);
        return;
      }

      for (const [k, v] of Object.entries(decision.headers)) res.set(k, v);
      req.payment = decision.receipt;
      next();
    } catch (err) {
      next(err);
    }
  };
}

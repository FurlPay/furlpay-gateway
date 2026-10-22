import http from "node:http";
import { Gateway, type GatewayOptions } from "../gateway.js";
import { noStoreHeaders } from "../protocol.js";
import { canonicalizeTarget, compileFreePaths } from "../path.js";

// ---------------------------------------------------------------------------
// Reverse-proxy mode.
//
// Put a paywall in front of an origin you do not want to modify — a legacy API,
// a model server, an MCP server, a static dataset. The origin stays untouched
// and never learns that it is being monetized.
//
//   furlpay-gateway expose http://localhost:8000 --price 0.01
//
// The origin MUST NOT be publicly reachable, or agents will simply route around
// the paywall. Bind it to loopback, or firewall it to this process.
// ---------------------------------------------------------------------------

export interface ProxyOptions extends GatewayOptions {
  /** Origin to forward paid requests to, e.g. "http://localhost:8000". */
  origin: string;
  port?: number;
  hostname?: string;
  /** Paths served free (health checks, docs, openapi.json). Exact or prefix*. */
  freePaths?: string[];
  /** Public base URL, when behind a TLS terminator. Resource identity — and so
   *  the quote binding — is derived from this, and it must match what the agent
   *  actually requested or every binding check fails. */
  publicUrl?: string;
}

/** Headers that are meaningful only for a single hop and must not be forwarded. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

/** A Host header we are willing to build a resource identity from. */
const HOST = /^(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;

function readRequestBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Build (but do not start) the paywalling reverse proxy.
 * Returns a standard `http.Server` — call `.listen()` yourself, or use
 * `startProxy` which does it for you.
 */
export function createProxy(opts: ProxyOptions): http.Server {
  const gateway = new Gateway(opts);
  const origin = opts.origin.replace(/\/+$/, "");
  const isFree = compileFreePaths(opts.freePaths ?? []);

  return http.createServer(async (req, res) => {
    const send = (status: number, body: unknown, headers: Record<string, string> = {}) => {
      const payload = JSON.stringify(body);
      res.writeHead(status, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
        ...headers,
      });
      res.end(payload);
    };

    // One canonical path drives the free decision, the quote binding, and the
    // upstream request. If those three ever see different strings, an origin
    // that decodes can be made to serve a resource nobody paid for.
    const target = canonicalizeTarget(req.url);
    if (!target.ok) {
      send(400, { error: "invalid_request_target", detail: target.reason }, noStoreHeaders);
      return;
    }
    const host = req.headers.host ?? "localhost";
    if (!opts.publicUrl && !HOST.test(host)) {
      send(400, { error: "invalid_host" }, noStoreHeaders);
      return;
    }
    const url = new URL(target.path + target.search, opts.publicUrl ?? `http://${host}`);
    if (url.pathname !== target.path) {
      // The URL parser rewrote a path we already declared canonical. Refuse
      // rather than guess which of the two the origin will see.
      send(400, { error: "invalid_request_target", detail: "path is not canonical" }, noStoreHeaders);
      return;
    }

    try {
      const method = (req.method ?? "GET").toUpperCase();
      const body = await readRequestBody(req);

      if (!isFree(url.pathname)) {
        let decision;
        try {
          decision = await gateway.authorize({
            method,
            url,
            headers: req.headers as Record<string, string | undefined>,
            body: body.length ? body : undefined,
          });
        } catch {
          // A facilitator outage or a throwing hook is never a free pass, and
          // the origin is never contacted.
          send(503, { error: "payment_verification_unavailable" }, noStoreHeaders);
          return;
        }
        if (decision.kind !== "allow") {
          send(decision.status, decision.body, decision.headers);
          return;
        }
        // Both dialects' receipts, plus the cache guards.
        for (const [k, v] of Object.entries(decision.headers)) res.setHeader(k, v);
      }

      // Forward to the origin.
      const forwardHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        const key = k.toLowerCase();
        if (HOP_BY_HOP.has(key)) continue;
        // The origin has no use for the payment credential, in either dialect.
        if (key === "x-payment" || key === "payment-signature") continue;
        if (typeof v === "string") forwardHeaders[k] = v;
        else if (Array.isArray(v)) forwardHeaders[k] = v.join(", ");
      }

      const upstream = await fetch(`${origin}${url.pathname}${url.search}`, {
        method,
        headers: forwardHeaders,
        body: method === "GET" || method === "HEAD" ? undefined : body,
        // Following a redirect here would fetch whatever the origin points at —
        // a free path redirecting to a paid one would serve it unpaid. The
        // client gets the 3xx and makes a new request, which is gated again.
        redirect: "manual",
      });

      upstream.headers.forEach((v, k) => {
        const key = k.toLowerCase();
        if (HOP_BY_HOP.has(key)) return;
        // Never let the origin's cache policy override ours on a paid response.
        if (key === "cache-control" || key === "vary") return;
        res.setHeader(k, v);
      });
      res.writeHead(upstream.status);
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.end(buf);
    } catch (e) {
      send(502, { error: "origin_unreachable", detail: (e as Error).message });
    }
  });
}

export interface RunningProxy {
  server: http.Server;
  port: number;
  close(): Promise<void>;
}

export function startProxy(opts: ProxyOptions): Promise<RunningProxy> {
  const server = createProxy(opts);
  const port = opts.port ?? 4402;
  const hostname = opts.hostname ?? "0.0.0.0";

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, hostname, () => {
      const addr = server.address();
      const actual = typeof addr === "object" && addr ? addr.port : port;
      resolve({
        server,
        port: actual,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

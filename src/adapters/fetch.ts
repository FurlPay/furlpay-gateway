import { Gateway, type GatewayDecision, type GatewayOptions } from "../gateway.js";
import type { SettlementReceipt } from "../protocol.js";

// ---------------------------------------------------------------------------
// Web-standard adapter — Next.js App Router, Hono, Cloudflare Workers, Deno,
// Bun, and anything else that speaks Request → Response.
//
// On Workers, node:crypto requires the `nodejs_compat` compatibility flag.
// ---------------------------------------------------------------------------

export type FetchHandler<Ctx = unknown> = (
  req: Request,
  ctx: Ctx
) => Response | Promise<Response>;

/** A handler that also receives the settlement receipt for the request. */
export type PaidHandler<Ctx = unknown> = (
  req: Request,
  ctx: Ctx,
  receipt: SettlementReceipt
) => Response | Promise<Response>;

function toResponse(decision: Exclude<GatewayDecision, { kind: "allow" }>): Response {
  return new Response(JSON.stringify(decision.body), {
    status: decision.status,
    headers: decision.headers,
  });
}

/** Read the body without consuming it for the wrapped handler. */
async function readBody(req: Request): Promise<string | undefined> {
  if (!req.body) return undefined;
  try {
    return await req.clone().text();
  } catch {
    return undefined;
  }
}

/**
 * Wrap a fetch-style handler so it only runs after payment.
 *
 * @example
 *   // app/api/weather/route.ts
 *   import { paywall } from "@furlpay/gateway";
 *
 *   const pay = paywall({
 *     price: 0.01,
 *     payTo: process.env.MERCHANT_WALLET!,
 *     quoteSecret: process.env.QUOTE_SECRET!,
 *     network: "base",
 *   });
 *
 *   export const GET = pay(async () => Response.json({ tempC: 17 }));
 */
export function paywall(opts: GatewayOptions) {
  const gateway = new Gateway(opts);

  function wrap<Ctx = unknown>(handler: PaidHandler<Ctx>): FetchHandler<Ctx> {
    return async (req: Request, ctx: Ctx): Promise<Response> => {
      const decision = await gateway.authorize({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: await readBody(req),
      });

      if (decision.kind !== "allow") return toResponse(decision);

      const res = await handler(req, ctx, decision.receipt);

      // Stamp the receipt and no-store onto whatever the handler returned. A
      // paid 200 that a CDN caches is a paid resource served free to the next
      // unpaid caller, so this is not optional.
      const out = new Response(res.body, res);
      for (const [k, v] of Object.entries(decision.headers)) out.headers.set(k, v);
      return out;
    };
  }

  wrap.gateway = gateway;
  return wrap;
}

/** Escape hatch for hand-rolled routing: get the decision, do what you like. */
export function createGateway(opts: GatewayOptions): Gateway {
  return new Gateway(opts);
}

# Security Policy

## Reporting a vulnerability

Email **security@furlpay.com**. Please do not open a public issue for a
vulnerability.

Include what you can: affected version, a description, and ideally a
reproduction. We aim to acknowledge within 72 hours.

## What this package is, and is not

`@furlpay/gateway` gates a resource behind an x402 payment. It **never holds a
private key, an RPC endpoint, or a gas balance** — a facilitator does the
on-chain work. That boundary is deliberate: it is what makes the gateway safe to
self-host, and it means a compromise of the gateway cannot move funds.

**This package has not been independently audited.** The defences below are
tested (`npm test`), not certified. If you are gating something valuable, read
the code — that is why `src/` ships in the tarball.

## Defences, and their limits

| Property | Enforced by | Limit |
| --- | --- | --- |
| Quote is bound to one resource, method, price | HMAC over `(method, resource, amount, quoteId, expiry[, bodyHash])`, constant-time compare | Only as strong as `quoteSecret`. There is **no default secret** — a published default would be a forgeable quote for every deployment that did not override it. |
| Quote is bound to one request body | `bodyHash` in the MAC (`POST`/`PUT`/`PATCH`) | Off if you set `bindBody: false`, or on Express without `captureRawBody`. The Express adapter **fails closed** rather than silently degrade. |
| One payment buys one delivery | Atomic single-use claim on the EIP-3009 nonce **and** the quoteId, burned before settlement | **The default `MemoryClaimStore` is single-instance only.** On N instances it is not replay protection at all — see below. |
| Cross-dialect double-spend | The quoteId claim is version-blind, so a quote spent as v1 cannot be re-spent as v2 | — |
| Settlement finality | Confirmation depth scaled to value (3 / 6 / 12) | The facilitator must report depth honestly. A dishonest facilitator can lie; choose one you trust. |
| Paid content is not cached | `Cache-Control: no-store` + `Vary` on both dialects' headers, on paid responses *and* 402s | In proxy mode the origin's own cache headers are overridden. Behind your own CDN, verify it honours `no-store`. |
| Facilitator outage | Fails closed | An unreachable facilitator costs you a sale, not the resource. |

## The one that bites people

Replay protection is a single-use claim. That claim must be **atomic and shared**,
or it is not protection.

A `Set` in module scope looks like replay protection and passes every local test,
because in dev there is one process. In production there are N instances, each
with its own empty `Set` — so the same payment replayed N times clears N
different sets and delivers the resource N times. **One payment, N deliveries.**

The default `MemoryClaimStore` reports `isDurable === false`. Assert on it:

```ts
if (process.env.NODE_ENV === "production" && !pay.gateway.replayProtectionDurable) {
  throw new Error("multi-instance deploy with in-memory replay protection");
}
```

Use `upstashClaimStore()` (or any `claimStoreFrom(setNx)`) in multi-instance
deployments. `upstashClaimStore()` throws rather than start without credentials,
because silently degrading to in-memory would *look* durable and not be.

## Reverse-proxy mode

The origin behind `startProxy()` **must not be publicly reachable**, or agents
will route around the paywall entirely. Bind it to loopback, or firewall it to
the gateway process.

## Related

Facilitator-side hardening (allowance overdraft, denial-of-settlement,
hidden-compute pricing) lives in [`@furlpay/x402-guard`](https://github.com/FurlPay/x402-guard).

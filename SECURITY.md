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
| Proxy decides on the path the origin serves | One canonical path for free check, price, binding and upstream; ambiguous targets refused | The origin must not case-fold or apply its own rewrites that map free paths onto paid ones. See below. |

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

### Request paths (fixed in 0.1.2)

Up to 0.1.1 the proxy matched `freePaths` against the still-encoded path and
forwarded it as-is. An origin that decodes before resolving (python
`http.server`, `serve-static`, most legacy servers) turned
`/docs%2f..%2fsecret` into `/secret`, so a paid resource behind a free prefix
was served without payment. `%5c` (backslash) worked the same way.

From 0.1.2 the proxy canonicalizes the request target once and uses that one
path for the free decision, the price, the quote binding, and the upstream
request. Targets whose meaning could differ between the gateway and an origin
are refused with `400 invalid_request_target` before any payment logic or
upstream request:

- encoded separators (`%2F`, `%5C`) and raw backslashes
- dot-segments in any spelling (`..`, `%2e%2e`, `.%2E`, `..;x`, Unicode lookalikes)
- nested encoding (`%25` followed by an escape), malformed escapes, invalid UTF-8
- empty interior segments (`/a//b`), control characters
- anything that is not origin-form (`http://host/x`, `//host/x`, `*`)

Escapes of unreserved characters are decoded (`/exp%65nsive` is `/expensive`),
so an encoded alias is priced and bound as the path it names.

Also in 0.1.2: upstream redirects are returned to the client rather than
followed (a free path redirecting to a paid one used to be fetched and served),
an exception during authorization is a `503` that never reaches the origin, and
a malformed `Host` is refused when `publicUrl` is unset.

**Migration.** A client that sends `%2F` inside a segment, `//`, or dot-segments
now gets a 400. Normal HTTP clients normalize dot-segments before sending and
never produce the others. If your origin genuinely needs `%2F` in a segment,
keep that route paid and put the gateway in front of it unchanged.

**`freePaths` prefixes are string prefixes.** `/docs*` also matches
`/docs-internal`. Write `/docs/*` to stop at the segment boundary. Patterns are
validated at startup; an invalid one is an error, not a silently dead rule.

**Case and Unicode.** The gateway does not case-fold. If your origin serves
`/Secret` and `/secret` as the same file (Windows, macOS default filesystems),
do not rely on case to separate free and paid paths.

## Related

Facilitator-side hardening (allowance overdraft, denial-of-settlement,
hidden-compute pricing) lives in [`@furlpay/x402-guard`](https://github.com/FurlPay/x402-guard).

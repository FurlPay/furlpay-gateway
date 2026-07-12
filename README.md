# @furlpay/gateway

**Paywall any API, MCP tool, dataset, or model endpoint with stablecoin pay-per-call.**

An x402 monetization gateway you host yourself. Point it at an endpoint, set a
price, and AI agents pay per request in USDC — no account, no API key, no
subscription, no invoice.

Framework-agnostic. Zero runtime dependencies. MIT.

```sh
npm install @furlpay/gateway
```

---

## Why this exists

Cloudflare and AWS both shipped x402 monetization at the edge in 2026, and both
route settlement through Coinbase's facilitator. That's fine if you're happy
being a tenant. This package is for everyone who wants the paywall to be *theirs*:
self-hosted, portable across clouds, with a facilitator you choose.

It speaks the same wire protocol as FurlPay's own priced resources, so any agent
that can pay `GET https://furlpay.com/api/x402/fx` can pay your endpoint with no
client changes.

## Quickstart

### 1. Any fetch-based framework (Next.js, Hono, Workers, Bun, Deno)

```ts
// app/api/weather/route.ts
import { paywall } from "@furlpay/gateway";

const pay = paywall({
  price: 0.01,                            // USD per call
  payTo: process.env.MERCHANT_WALLET!,    // your wallet
  quoteSecret: process.env.QUOTE_SECRET!, // see "Configuration"
  network: "base",
});

export const GET = pay(async (req, ctx, receipt) => {
  // Only runs after payment has settled on-chain.
  return Response.json({ tempC: 17, paidBy: receipt.payer });
});
```

### 2. Express

```ts
import express from "express";
import { expressPaywall, captureRawBody } from "@furlpay/gateway/express";

const app = express();
app.use(express.json({ verify: captureRawBody })); // needed for body binding

app.get("/api/weather", expressPaywall({ price: 0.01, payTo, quoteSecret }), (req, res) => {
  res.json({ tempC: 17, paidBy: req.payment.payer });
});
```

### 3. Reverse proxy — monetize something you can't modify

```sh
npx @furlpay/gateway secret          # → generates a quote secret
export QUOTE_SECRET=<that value>

npx @furlpay/gateway expose http://localhost:8000 \
  --price 0.01 \
  --pay-to 0xYourWallet \
  --network base \
  --free /health,/openapi.json
```

Your origin stays untouched and never learns it's being monetized. **The origin
must not be publicly reachable**, or agents will simply route around the paywall.

---

## How a payment actually works

```
agent                          gateway                      facilitator      chain
  │  GET /weather                 │                              │             │
  ├──────────────────────────────►│                              │             │
  │  402 + PaymentRequirements    │                              │             │
  │◄──────────────────────────────┤                              │             │
  │                               │                              │             │
  │  signs EIP-3009 authorization │                              │             │
  │  (OFF-CHAIN — no gas, no tx)  │                              │             │
  │                               │                              │             │
  │  GET /weather                 │                              │             │
  │  X-PAYMENT: base64(auth)      │                              │             │
  ├──────────────────────────────►│  verify + settle             │             │
  │                               ├─────────────────────────────►│  submits,   │
  │                               │                              │  pays gas   │
  │                               │                              ├────────────►│
  │                               │  settled @ N confirmations   │             │
  │                               │◄─────────────────────────────┤             │
  │  200 + X-PAYMENT-RESPONSE     │                              │             │
  │◄──────────────────────────────┤                              │             │
```

**The agent never submits a transaction and never holds gas.** It signs an
authorization; the facilitator submits it and pays the gas. If you read a guide
that tells you to "verify the transaction hash the client sends you via RPC" —
that guide is not describing x402. It's describing a protocol that forces every
agent to hold native gas on every chain it might want to buy from, which is
exactly the problem x402 exists to remove.

## Configuration

| Option | Default | Notes |
| --- | --- | --- |
| `price` | — | USD per call. A function `(ctx) => number` prices per-route or per-caller. |
| `payTo` | — | Wallet that receives payment. |
| `quoteSecret` | — | HMAC secret binding quotes to resources. **No default, by design.** |
| `network` | `base` | `arbitrum`, `base`, `polygon`, `solana`, + testnets. |
| `asset` | canonical USDC | Override for a non-USDC token. |
| `facilitator` | FurlPay | URL or a `FacilitatorClient`. Any x402 facilitator works. |
| `claimStore` | in-memory | **Must be shared in multi-instance deploys — see below.** |
| `bindBody` | `true` | Bind the quote to a hash of the request body. |
| `settle` | `true` | `false` verifies but does not collect. Rarely what you want. |
| `onSettled` | — | Fires on confirmed settlement — ledger, webhooks, metering. |

`quoteSecret` has no default because a default would be a *published* default,
and a published default is a forgeable quote for every deployment that didn't
override it. Generate one:

```sh
npx @furlpay/gateway secret
```

## Running more than one instance

Replay protection is a single-use claim on the EIP-3009 nonce and the quote ID.
That claim must be **atomic and shared**, or it isn't protection.

The classic bug: a `Set` in module scope looks like replay protection and passes
every local test, because in dev there's one process. In production there are N
instances, each with its own empty `Set`, so the same `X-PAYMENT` replayed N
times clears N different Sets and delivers the resource N times — **one payment,
N deliveries.**

The default `MemoryClaimStore` is correct on exactly one instance and reports
`isDurable === false`. On more than one, pass a shared store:

```ts
import { Redis } from "@upstash/redis";
import { paywall, claimStoreFrom } from "@furlpay/gateway";

const redis = Redis.fromEnv();

const pay = paywall({
  price: 0.01,
  payTo,
  quoteSecret,
  claimStore: claimStoreFrom(
    (key, ttl) => redis.set(key, 1, { nx: true, ex: ttl }).then((r) => r === "OK")
  ),
});
```

Assert it at boot so you find out at deploy time, not during an incident:

```ts
if (process.env.NODE_ENV === "production" && !pay.gateway.replayProtectionDurable) {
  throw new Error("multi-instance deploy with in-memory replay protection");
}
```

## What this defends against

Every one of these is covered by a test in `test/gateway.test.js`.

| Attack | Defence |
| --- | --- |
| **Cross-resource substitution** — pay $0.001 for `/weather`, present it at `/gpt-5-inference` | Quotes carry an HMAC over `(method, resource, amount, quoteId, expiry[, bodyHash])`. A payment minted for one resource fails the binding check at any other — *even at the same price*. |
| **Body substitution** — pay for `{"model":"small"}`, retry with `{"model":"large"}` | The quote is bound to a hash of the exact body it was issued for. |
| **Replay / duplicate settlement** — send one `X-PAYMENT` N times | The nonce and quote ID are burned via an atomic single-use claim, before settlement. Concurrent replays of one payment yield exactly one grant. |
| **Revert-grant** — resource delivered on a settlement that later reorgs | Confirmation depth scales with value: 3 under $1, 6 under $10, 12 above. Shallower than required → no delivery. |
| **Cache leakage** — a CDN caches the paid 200 and serves it free | `Cache-Control: no-store` + `Vary: X-PAYMENT` on paid responses *and* on 402 quotes. In proxy mode the origin's own cache headers are overridden. |
| **Underpayment** — pay `9000` against a `10000` quote | Amounts compare as integers. (`"9000" > "10000"` lexicographically — a string compare here is a real vulnerability.) |
| **Quote forgery / tampering** | Constant-time HMAC compare. Amount, recipient, network, and expiry are all re-derived server-side; the client's echo is a lookup key, never an assertion. |
| **Facilitator outage** | Fails closed. A facilitator you can't reach costs you a sale, not the resource. |
| **Settlement error** | The nonce stays burned — a failed settle may still land on-chain, so freeing it would reopen replay against a payment that does confirm. Honest retries sign a fresh nonce, so this never blocks a real payer. |

For facilitator-side hardening (allowance overdraft, denial-of-settlement,
hidden-compute pricing), see [`@furlpay/x402-guard`](../x402-guard).

## Choosing a facilitator

The facilitator is the only party that touches a chain. The gateway never needs a
private key, an RPC endpoint, or a gas balance — which is what makes it safe to
self-host.

```ts
paywall({ facilitator: "https://furlpay.com/api/x402/facilitator" }) // default
paywall({ facilitator: "https://x402.org/facilitator" })             // or anyone else
paywall({ facilitator: myCustomClient })                             // or your own
```

## License

MIT

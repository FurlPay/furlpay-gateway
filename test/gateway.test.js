import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Gateway, MemoryClaimStore, b64decode, decodeReceipt } from "../dist/index.js";

// ---------------------------------------------------------------------------
// The attack suite. Each test presents a payment a naive gateway would honour,
// and asserts this one does not — in BOTH x402 dialects, because a defence that
// only holds on v1 is not a defence.
// ---------------------------------------------------------------------------

const SECRET = "test_secret_at_least_16_chars_long";
const PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const PAYER = "0xAbC0000000000000000000000000000000000001";

function okFacilitator(overrides = {}) {
  return {
    async verify() {
      return { isValid: true, payer: PAYER };
    },
    async settle(req) {
      return {
        success: true,
        transaction: "0x" + "de".repeat(32),
        network: req.paymentRequirements.network,
        payer: PAYER,
        confirmations: 12,
        ...overrides,
      };
    },
    async supported() {
      return [];
    },
  };
}

function makeGateway(opts = {}) {
  return new Gateway({
    price: (ctx) => (ctx.url.pathname === "/expensive" ? 2.0 : 0.01),
    payTo: PAY_TO,
    quoteSecret: SECRET,
    network: "base",
    facilitator: okFacilitator(),
    claimStore: new MemoryClaimStore(),
    ...opts,
  });
}

const authorization = ({ nonce, value, to } = {}, req) => ({
  from: PAYER,
  to: to ?? PAY_TO,
  value: value ?? req.amount,
  validAfter: "0",
  validBefore: String(Math.floor(Date.now() / 1000) + 600),
  nonce: nonce ?? crypto.randomBytes(32).toString("hex"),
});

const SIG = "0x" + "ab".repeat(65);

/** Read the v1 requirements out of the 402 body. */
const v1req = (challenge) => challenge.body.accepts[0];

/** Read the v2 requirements out of the PAYMENT-REQUIRED header. */
const v2req = (challenge) => b64decode(challenge.headers["PAYMENT-REQUIRED"]).accepts[0];

/** Sign as a v1 client → X-PAYMENT. */
function signV1(req, tamper = {}) {
  const payload = {
    x402Version: 1,
    scheme: "exact",
    network: tamper.network ?? req.network,
    payload: { signature: SIG, authorization: authorization(tamper, { amount: req.maxAmountRequired }) },
    extra: req.extra,
  };
  return { "x-payment": Buffer.from(JSON.stringify(payload)).toString("base64") };
}

/** Sign as a v2 client → PAYMENT-SIGNATURE. */
function signV2(req, tamper = {}) {
  const payload = {
    x402Version: 2,
    accepted: { ...req, network: tamper.network ?? req.network },
    payload: { signature: SIG, authorization: authorization(tamper, { amount: req.amount }) },
  };
  return { "payment-signature": Buffer.from(JSON.stringify(payload)).toString("base64") };
}

/** Run the same test body against both dialects. */
const DIALECTS = [
  { name: "v1", pick: v1req, sign: signV1 },
  { name: "v2", pick: v2req, sign: signV2 },
];

const GET = (url, headers = {}, body) => ({ method: "GET", url, headers, body });

// ── negotiation ───────────────────────────────────────────────────────────

test("a 402 advertises BOTH dialects at once", async () => {
  const gw = makeGateway();
  const d = await gw.authorize(GET("https://api.dev/weather"));

  assert.equal(d.kind, "challenge");
  assert.equal(d.status, 402);

  // v1 in the body...
  assert.equal(d.body.x402Version, 1);
  assert.equal(d.body.accepts[0].maxAmountRequired, "10000");
  assert.equal(d.body.accepts[0].resource, "https://api.dev/weather");

  // ...v2 in the PAYMENT-REQUIRED header, which is what v2 moving payment data
  // out of the body is FOR.
  const v2 = b64decode(d.headers["PAYMENT-REQUIRED"]);
  assert.equal(v2.x402Version, 2);
  assert.equal(v2.accepts[0].amount, "10000", "v2 renames maxAmountRequired -> amount");
  assert.equal(v2.resource.url, "https://api.dev/weather", "v2 hoists resource to ResourceInfo");
  assert.equal(v2.accepts[0].maxAmountRequired, undefined, "v2 must not carry the v1 field");

  assert.match(d.headers["Cache-Control"], /no-store/);
  assert.match(d.headers["Vary"], /PAYMENT-SIGNATURE/);
});

test("v2 discovery metadata rides in the 402 (no proprietary index needed)", async () => {
  const gw = makeGateway({
    serviceName: "Acme Weather",
    tags: ["weather", "forecast"],
    iconUrl: "https://acme.dev/icon.png",
  });
  const d = await gw.authorize(GET("https://api.dev/weather"));
  const v2 = b64decode(d.headers["PAYMENT-REQUIRED"]);

  assert.equal(v2.resource.serviceName, "Acme Weather");
  assert.deepEqual(v2.resource.tags, ["weather", "forecast"]);
  assert.equal(v2.resource.iconUrl, "https://acme.dev/icon.png");
});

test("the facilitator is called in the dialect the client spoke", async () => {
  const seen = [];
  const spy = {
    async verify() {
      return { isValid: true, payer: PAYER };
    },
    async settle(req) {
      seen.push(req.x402Version);
      return { success: true, transaction: "0xok", network: "base", payer: PAYER, confirmations: 12 };
    },
    async supported() {
      return [];
    },
  };

  for (const { pick, sign } of DIALECTS) {
    const gw = makeGateway({ facilitator: spy });
    const c = await gw.authorize(GET("https://api.dev/weather"));
    await gw.authorize(GET("https://api.dev/weather", sign(pick(c))));
  }
  assert.deepEqual(seen, [1, 2]);
});

test("facilitatorVersion pins the dialect for a v1-only facilitator", async () => {
  const seen = [];
  const gw = makeGateway({
    facilitatorVersion: 1,
    facilitator: {
      async verify() {
        return { isValid: true, payer: PAYER };
      },
      async settle(req) {
        seen.push(req.x402Version);
        assert.ok(req.paymentRequirements.maxAmountRequired, "must be downconverted to the v1 shape");
        return { success: true, transaction: "0xok", network: "base", payer: PAYER, confirmations: 12 };
      },
      async supported() {
        return [];
      },
    },
  });

  // A v2 client, but the facilitator only speaks v1.
  const c = await gw.authorize(GET("https://api.dev/weather"));
  const d = await gw.authorize(GET("https://api.dev/weather", signV2(v2req(c))));
  assert.equal(d.kind, "allow");
  assert.deepEqual(seen, [1]);
});

// ── per-dialect suite ─────────────────────────────────────────────────────

for (const { name, pick, sign } of DIALECTS) {
  const quote = async (gw, url, body) => pick(await gw.authorize(GET(url, {}, body)));

  test(`[${name}] a correctly signed payment unlocks the resource`, async () => {
    const gw = makeGateway();
    const req = await quote(gw, "https://api.dev/weather");
    const d = await gw.authorize(GET("https://api.dev/weather", sign(req)));

    assert.equal(d.kind, "allow");
    assert.equal(d.receipt.payer, PAYER);
    assert.equal(d.receipt.amountAtomic, "10000");

    // Both receipts are emitted, so an SDK expecting either finds its own.
    assert.equal(decodeReceipt(d.headers["X-PAYMENT-RESPONSE"]).payer, PAYER);
    assert.equal(b64decode(d.headers["PAYMENT-RESPONSE"]).success, true);
    assert.match(d.headers["Cache-Control"], /no-store/);
  });

  test(`[${name}] replaying the same payment does not unlock the resource twice`, async () => {
    const gw = makeGateway();
    const headers = sign(await quote(gw, "https://api.dev/weather"));

    assert.equal((await gw.authorize(GET("https://api.dev/weather", headers))).kind, "allow");
    const second = await gw.authorize(GET("https://api.dev/weather", headers));
    assert.equal(second.kind, "challenge");
    assert.match(second.body.error, /already used|replay/i);
  });

  test(`[${name}] concurrent replays of one payment yield exactly one grant`, async () => {
    const gw = makeGateway();
    const headers = sign(await quote(gw, "https://api.dev/weather"));
    const results = await Promise.all(
      Array.from({ length: 8 }, () => gw.authorize(GET("https://api.dev/weather", headers)))
    );
    assert.equal(results.filter((r) => r.kind === "allow").length, 1);
  });

  test(`[${name}] a payment for one resource cannot unlock another at the SAME price`, async () => {
    // Equal prices, so the amount check cannot be what saves us — this isolates
    // the binding MAC as the only thing standing in the way.
    const gw = makeGateway({ price: 0.01 });
    const headers = sign(await quote(gw, "https://api.dev/cheap-data"));

    const d = await gw.authorize(GET("https://api.dev/premium-model", headers));
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /binding mismatch/i);
  });

  test(`[${name}] a payment for a cheap resource cannot unlock an expensive one`, async () => {
    const gw = makeGateway();
    const headers = sign(await quote(gw, "https://api.dev/weather")); // $0.01
    const d = await gw.authorize(GET("https://api.dev/expensive", headers)); // $2.00
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /insufficient amount/i);
  });

  test(`[${name}] a payment for GET cannot be presented against POST on the same path`, async () => {
    const gw = makeGateway({ price: 0.01 });
    const headers = sign(await quote(gw, "https://api.dev/infer"));
    const d = await gw.authorize({ method: "POST", url: "https://api.dev/infer", headers });
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /binding mismatch/i);
  });

  test(`[${name}] a payment quoted for one request body cannot unlock another`, async () => {
    const gw = makeGateway({ price: 0.01 });
    const small = JSON.stringify({ model: "small", tokens: 10 });
    const large = JSON.stringify({ model: "large", tokens: 100000 });

    const req = pick(await gw.authorize({ method: "POST", url: "https://api.dev/infer", headers: {}, body: small }));
    const d = await gw.authorize({
      method: "POST",
      url: "https://api.dev/infer",
      headers: sign(req),
      body: large, // only the body swapped
    });
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /body does not match/i);
  });

  test(`[${name}] the body the quote was issued for is honoured`, async () => {
    const gw = makeGateway({ price: 0.01 });
    const body = JSON.stringify({ model: "small" });
    const req = pick(await gw.authorize({ method: "POST", url: "https://api.dev/infer", headers: {}, body }));
    const d = await gw.authorize({ method: "POST", url: "https://api.dev/infer", headers: sign(req), body });
    assert.equal(d.kind, "allow");
  });

  test(`[${name}] a payment addressed to another wallet is refused`, async () => {
    const gw = makeGateway();
    const req = await quote(gw, "https://api.dev/weather");
    const d = await gw.authorize(
      GET("https://api.dev/weather", sign(req, { to: "0x000000000000000000000000000000000000dEaD" }))
    );
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /not addressed to this recipient/i);
  });

  test(`[${name}] underpayment is refused (amounts compare as integers, not strings)`, async () => {
    const gw = makeGateway();
    const req = await quote(gw, "https://api.dev/weather");
    // "9000" > "10000" lexicographically. Only an integer compare catches this.
    const d = await gw.authorize(GET("https://api.dev/weather", sign(req, { value: "9000" })));
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /insufficient amount/i);
  });

  test(`[${name}] a payment on the wrong network is refused`, async () => {
    const gw = makeGateway();
    const req = await quote(gw, "https://api.dev/weather");
    const d = await gw.authorize(GET("https://api.dev/weather", sign(req, { network: "polygon" })));
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /wrong network/i);
  });

  test(`[${name}] a forged binding is refused`, async () => {
    const gw = makeGateway();
    const req = await quote(gw, "https://api.dev/weather");
    req.extra = { ...req.extra, binding: crypto.randomBytes(32).toString("hex") };
    const d = await gw.authorize(GET("https://api.dev/weather", sign(req)));
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /binding mismatch/i);
  });

  test(`[${name}] an expired quote is refused`, async () => {
    const gw = makeGateway();
    const req = await quote(gw, "https://api.dev/weather");
    req.extra = { ...req.extra, expiresAt: Math.floor(Date.now() / 1000) - 1 };
    const d = await gw.authorize(GET("https://api.dev/weather", sign(req)));
    assert.equal(d.kind, "challenge");
    // Tampering with expiresAt also breaks the MAC; either refusal is correct.
    assert.match(d.body.error, /expired|binding mismatch/i);
  });

  test(`[${name}] a failed settlement does not release the resource`, async () => {
    const gw = makeGateway({
      facilitator: {
        async verify() {
          return { isValid: true, payer: PAYER };
        },
        async settle() {
          return { success: false, network: "base", errorReason: "insufficient_funds" };
        },
        async supported() {
          return [];
        },
      },
    });
    const d = await gw.authorize(GET("https://api.dev/weather", sign(await quote(gw, "https://api.dev/weather"))));
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /insufficient_funds/);
  });

  test(`[${name}] a settlement below the required confirmation depth is refused`, async () => {
    const gw = makeGateway({ price: 50, facilitator: okFacilitator({ confirmations: 2 }) }); // $50 → 12
    const d = await gw.authorize(GET("https://api.dev/dataset", sign(await quote(gw, "https://api.dev/dataset"))));
    assert.equal(d.kind, "challenge");
    assert.match(d.body.error, /insufficient confirmations \(2\/12\)/i);
  });

  test(`[${name}] an unreachable facilitator fails closed`, async () => {
    const gw = makeGateway({
      facilitator: {
        async verify() {
          return { isValid: false, invalidReason: "facilitator_unreachable" };
        },
        async settle() {
          return { success: false, network: "base", errorReason: "facilitator_unreachable" };
        },
        async supported() {
          return [];
        },
      },
    });
    const d = await gw.authorize(GET("https://api.dev/weather", sign(await quote(gw, "https://api.dev/weather"))));
    assert.notEqual(d.kind, "allow");
  });

  test(`[${name}] a burned nonce stays burned after a failed settlement`, async () => {
    // The tx may still land on-chain, so freeing the nonce would reopen replay
    // against a payment that does confirm.
    let attempt = 0;
    const gw = makeGateway({
      facilitator: {
        async verify() {
          return { isValid: true, payer: PAYER };
        },
        async settle() {
          return ++attempt === 1
            ? { success: false, network: "base", errorReason: "timeout" }
            : { success: true, transaction: "0xlate", network: "base", payer: PAYER, confirmations: 12 };
        },
        async supported() {
          return [];
        },
      },
    });
    const headers = sign(await quote(gw, "https://api.dev/weather"));
    assert.equal((await gw.authorize(GET("https://api.dev/weather", headers))).kind, "challenge");

    const retry = await gw.authorize(GET("https://api.dev/weather", headers));
    assert.equal(retry.kind, "challenge");
    assert.match(retry.body.error, /already used|replay/i);
  });
}

// ── cross-dialect ─────────────────────────────────────────────────────────

test("a quote spent in one dialect cannot be re-spent in the other", async () => {
  // One 402 mints ONE quote and renders it in both dialects — same quoteId. An
  // agent that pays it as v1 and then re-presents the same quote as v2 (fresh
  // EIP-3009 nonce, so the nonce claim won't catch it) is double-spending one
  // quote. Only the quoteId claim stops this, and it must be dialect-blind.
  const gw = makeGateway();
  const challenge = await gw.authorize(GET("https://api.dev/weather"));

  const first = await gw.authorize(GET("https://api.dev/weather", signV1(v1req(challenge))));
  assert.equal(first.kind, "allow");

  const second = await gw.authorize(GET("https://api.dev/weather", signV2(v2req(challenge))));
  assert.equal(second.kind, "challenge", "one quote must buy exactly one delivery, in any dialect");
  assert.match(second.body.error, /already redeemed|already used|replay/i);
});

// ── v2-specific ───────────────────────────────────────────────────────────

test("[v2] `upto` settling less than authorized is reported honestly in the receipt", async () => {
  // v2's upto scheme settles the ACTUAL cost, which may be below the authorized
  // maximum. The receipt must report what was taken, not what was authorized.
  const gw = makeGateway({
    price: 1.0,
    facilitator: okFacilitator({ amount: "250000" }), // $0.25 actually consumed
  });
  const c = await gw.authorize(GET("https://api.dev/infer"));
  const d = await gw.authorize(GET("https://api.dev/infer", signV2(v2req(c))));

  assert.equal(d.kind, "allow");
  assert.equal(d.receipt.amountAtomic, "250000", "receipt must report the settled amount");
  assert.equal(b64decode(d.headers["PAYMENT-RESPONSE"]).amount, "250000");
});

test("a malformed payment header is a 400, never a free resource", async () => {
  const gw = makeGateway();
  for (const headers of [{ "x-payment": "!!!garbage!!!" }, { "payment-signature": "!!!garbage!!!" }]) {
    const d = await gw.authorize(GET("https://api.dev/weather", headers));
    assert.equal(d.kind, "reject");
    assert.equal(d.status, 400);
  }
});

test("an oversized payment header is rejected before parsing", async () => {
  const gw = makeGateway();
  const d = await gw.authorize(GET("https://api.dev/weather", { "payment-signature": "x".repeat(9000) }));
  assert.equal(d.kind, "reject");
  assert.match(d.body.error, /too large/i);
});

// ── configuration is fail-closed ──────────────────────────────────────────

test("a weak or missing quote secret is refused at construction", () => {
  assert.throws(() => new Gateway({ price: 0.01, payTo: PAY_TO, quoteSecret: "" }), /quoteSecret/);
  assert.throws(() => new Gateway({ price: 0.01, payTo: PAY_TO, quoteSecret: "short" }), /quoteSecret/);
});

test("a missing payTo is refused at construction", () => {
  assert.throws(() => new Gateway({ price: 0.01, payTo: "", quoteSecret: SECRET }), /payTo/);
});

test("an unknown network without an explicit asset is refused at construction", () => {
  assert.throws(
    () => new Gateway({ price: 0.01, payTo: PAY_TO, quoteSecret: SECRET, network: "dogecoin" }),
    /no canonical USDC/
  );
});

test("in-memory replay protection reports itself as non-durable", () => {
  assert.equal(makeGateway().replayProtectionDurable, false);
});

// ── claim store ───────────────────────────────────────────────────────────

test("MemoryClaimStore burns a key exactly once", async () => {
  const store = new MemoryClaimStore();
  assert.equal(await store.claim("k", 60), true);
  assert.equal(await store.claim("k", 60), false);
  assert.equal(await store.claim("other", 60), true);
});

test("MemoryClaimStore stays bounded under a flood of distinct keys", async () => {
  const store = new MemoryClaimStore(100);
  for (let i = 0; i < 500; i++) await store.claim(`k${i}`, 60);
  assert.ok(store.size <= 100, `expected <=100 entries, got ${store.size}`);
});

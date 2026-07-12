import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Gateway, MemoryClaimStore, decodeReceipt } from "../dist/index.js";

// ---------------------------------------------------------------------------
// These tests are the attack suite. Each one presents a payment that a naive
// gateway would honour, and asserts that this one does not.
// ---------------------------------------------------------------------------

const SECRET = "test_secret_at_least_16_chars_long";
const PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const PAYER = "0xAbC0000000000000000000000000000000000001";

/** Facilitator that always settles cleanly at max depth. */
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

/** Build the X-PAYMENT header a well-behaved agent would send for `req`. */
function sign(requirements, { nonce, value, to, network } = {}) {
  const payload = {
    x402Version: 1,
    scheme: "exact",
    network: network ?? requirements.network,
    payload: {
      signature: "0x" + "ab".repeat(65),
      authorization: {
        from: PAYER,
        to: to ?? requirements.payTo,
        value: value ?? requirements.maxAmountRequired,
        validAfter: "0",
        validBefore: String(Math.floor(Date.now() / 1000) + 600),
        nonce: nonce ?? crypto.randomBytes(32).toString("hex"),
      },
    },
    extra: {
      quoteId: requirements.extra.quoteId,
      binding: requirements.extra.binding,
      expiresAt: requirements.extra.expiresAt,
      ...(requirements.extra.bodyHash ? { bodyHash: requirements.extra.bodyHash } : {}),
    },
  };
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}

const GET = (url, header, body) => ({
  method: "GET",
  url,
  headers: header ? { "x-payment": header } : {},
  body,
});

// ── happy path ────────────────────────────────────────────────────────────

test("an unpaid request gets a 402 carrying a payable quote", async () => {
  const gw = makeGateway();
  const d = await gw.authorize(GET("https://api.dev/weather"));

  assert.equal(d.kind, "challenge");
  assert.equal(d.status, 402);
  assert.equal(d.body.x402Version, 1);
  assert.equal(d.body.accepts.length, 1);

  const req = d.body.accepts[0];
  assert.equal(req.scheme, "exact");
  assert.equal(req.network, "base");
  assert.equal(req.maxAmountRequired, "10000"); // $0.01
  assert.equal(req.payTo, PAY_TO);
  assert.equal(req.resource, "https://api.dev/weather");
  assert.ok(req.extra.quoteId && req.extra.binding && req.extra.expiresAt);

  // A 402 carrying a single-use quote must never be cached.
  assert.match(d.headers["Cache-Control"], /no-store/);
});

test("a correctly signed payment unlocks the resource and returns a receipt", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const d = await gw.authorize(GET("https://api.dev/weather", sign(body.accepts[0])));

  assert.equal(d.kind, "allow");
  assert.equal(d.receipt.payer, PAYER);
  assert.equal(d.receipt.amountAtomic, "10000");
  assert.equal(d.receipt.resource, "https://api.dev/weather");

  const receipt = decodeReceipt(d.headers["X-PAYMENT-RESPONSE"]);
  assert.equal(receipt.payer, PAYER);
  assert.match(d.headers["Cache-Control"], /no-store/);
});

// ── attack: replay ────────────────────────────────────────────────────────

test("replaying the same payment does not unlock the resource twice", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const header = sign(body.accepts[0]);

  const first = await gw.authorize(GET("https://api.dev/weather", header));
  assert.equal(first.kind, "allow");

  const second = await gw.authorize(GET("https://api.dev/weather", header));
  assert.equal(second.kind, "challenge", "a replayed payment must not be honoured");
  assert.match(second.body.error, /already used|replay/i);
});

test("concurrent replays of one payment yield exactly one grant", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const header = sign(body.accepts[0]);

  const results = await Promise.all(
    Array.from({ length: 8 }, () => gw.authorize(GET("https://api.dev/weather", header)))
  );
  const granted = results.filter((r) => r.kind === "allow");
  assert.equal(granted.length, 1, "one payment must buy exactly one delivery");
});

// ── attack: cross-resource substitution ───────────────────────────────────

test("a payment for one resource cannot unlock a different resource at the same price", async () => {
  // Same price on both, so the amount check cannot be what saves us — this
  // isolates the binding MAC as the only thing standing in the way.
  const gw = makeGateway({ price: 0.01 });
  const { body } = await gw.authorize(GET("https://api.dev/cheap-data"));
  const header = sign(body.accepts[0]);

  const d = await gw.authorize(GET("https://api.dev/premium-model", header));
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /binding mismatch/i);
});

test("a payment for a cheap resource cannot unlock an expensive one", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather")); // $0.01
  const header = sign(body.accepts[0]);

  const d = await gw.authorize(GET("https://api.dev/expensive", header)); // $2.00
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /insufficient amount/i);
});

test("a payment for GET cannot be presented against POST on the same path", async () => {
  const gw = makeGateway({ price: 0.01 });
  const { body } = await gw.authorize(GET("https://api.dev/infer"));
  const header = sign(body.accepts[0]);

  const d = await gw.authorize({
    method: "POST",
    url: "https://api.dev/infer",
    headers: { "x-payment": header },
  });
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /binding mismatch/i);
});

// ── attack: body substitution ─────────────────────────────────────────────

test("a payment quoted for one request body cannot unlock another", async () => {
  const gw = makeGateway({ price: 0.01 });
  const cheapBody = JSON.stringify({ model: "small", tokens: 10 });
  const dearBody = JSON.stringify({ model: "large", tokens: 100000 });

  const quote = await gw.authorize({
    method: "POST",
    url: "https://api.dev/infer",
    headers: {},
    body: cheapBody,
  });
  const header = sign(quote.body.accepts[0]);

  // Same path, same price, same signed authorization — only the body swapped.
  const d = await gw.authorize({
    method: "POST",
    url: "https://api.dev/infer",
    headers: { "x-payment": header },
    body: dearBody,
  });
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /body does not match/i);
});

test("the same body the quote was issued for is honoured", async () => {
  const gw = makeGateway({ price: 0.01 });
  const body = JSON.stringify({ model: "small" });

  const quote = await gw.authorize({ method: "POST", url: "https://api.dev/infer", headers: {}, body });
  const d = await gw.authorize({
    method: "POST",
    url: "https://api.dev/infer",
    headers: { "x-payment": sign(quote.body.accepts[0]) },
    body,
  });
  assert.equal(d.kind, "allow");
});

// ── attack: tampering ─────────────────────────────────────────────────────

test("a payment addressed to another wallet is refused", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const header = sign(body.accepts[0], { to: "0x000000000000000000000000000000000000dEaD" });

  const d = await gw.authorize(GET("https://api.dev/weather", header));
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /not addressed to this recipient/i);
});

test("an underpayment is refused, and amounts compare as integers not strings", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));

  // "9000" > "10000" lexicographically. Only an integer compare catches this.
  const d = await gw.authorize(GET("https://api.dev/weather", sign(body.accepts[0], { value: "9000" })));
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /insufficient amount/i);
});

test("a payment on the wrong network is refused", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const d = await gw.authorize(GET("https://api.dev/weather", sign(body.accepts[0], { network: "polygon" })));
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /wrong network/i);
});

test("a forged binding (no secret) is refused", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const req = body.accepts[0];
  req.extra.binding = crypto.randomBytes(32).toString("hex"); // attacker guesses

  const d = await gw.authorize(GET("https://api.dev/weather", sign(req)));
  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /binding mismatch/i);
});

test("an expired quote is refused", async () => {
  const gw = makeGateway();
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const req = body.accepts[0];
  req.extra.expiresAt = Math.floor(Date.now() / 1000) - 1; // already gone

  const d = await gw.authorize(GET("https://api.dev/weather", sign(req)));
  assert.equal(d.kind, "challenge");
  // Tampering with expiresAt also breaks the MAC, so either guard may fire —
  // both are correct refusals.
  assert.match(d.body.error, /expired|binding mismatch/i);
});

test("a malformed X-PAYMENT is a 400, never a free resource", async () => {
  const gw = makeGateway();
  const d = await gw.authorize(GET("https://api.dev/weather", "!!!garbage!!!"));
  assert.equal(d.kind, "reject");
  assert.equal(d.status, 400);
});

// ── settlement failures fail closed ───────────────────────────────────────

test("a failed settlement does not release the resource", async () => {
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
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const d = await gw.authorize(GET("https://api.dev/weather", sign(body.accepts[0])));

  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /insufficient_funds/);
});

test("a settlement below the required confirmation depth does not release the resource", async () => {
  const gw = makeGateway({
    price: 50, // $50 → 12 confirmations required
    facilitator: okFacilitator({ confirmations: 2 }),
  });
  const { body } = await gw.authorize(GET("https://api.dev/dataset"));
  const d = await gw.authorize(GET("https://api.dev/dataset", sign(body.accepts[0])));

  assert.equal(d.kind, "challenge");
  assert.match(d.body.error, /insufficient confirmations \(2\/12\)/i);
});

test("an unreachable facilitator fails closed", async () => {
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
  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const d = await gw.authorize(GET("https://api.dev/weather", sign(body.accepts[0])));
  assert.notEqual(d.kind, "allow", "a facilitator we cannot reach must not grant the resource");
});

test("a burned nonce stays burned after a failed settlement", async () => {
  // The tx may still land on-chain, so freeing the nonce would reopen it for
  // replay against a payment that does confirm.
  let attempt = 0;
  const gw = makeGateway({
    facilitator: {
      async verify() {
        return { isValid: true, payer: PAYER };
      },
      async settle(req) {
        attempt++;
        if (attempt === 1) return { success: false, network: "base", errorReason: "timeout" };
        return {
          success: true,
          transaction: "0xlate",
          network: req.paymentRequirements.network,
          payer: PAYER,
          confirmations: 12,
        };
      },
      async supported() {
        return [];
      },
    },
  });

  const { body } = await gw.authorize(GET("https://api.dev/weather"));
  const header = sign(body.accepts[0]);

  const first = await gw.authorize(GET("https://api.dev/weather", header));
  assert.equal(first.kind, "challenge");

  const retry = await gw.authorize(GET("https://api.dev/weather", header));
  assert.equal(retry.kind, "challenge");
  assert.match(retry.body.error, /already used|replay/i);
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
  const gw = makeGateway();
  assert.equal(gw.replayProtectionDurable, false);
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

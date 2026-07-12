import test from "node:test";
import assert from "node:assert/strict";
import {
  atomicAmount,
  b64encode,
  bindingMac,
  claimStoreFrom,
  decodePayment,
  decodeReceipt,
  detectVersion,
  encodeReceiptV1,
  encodeReceiptV2,
  hashBody,
  requiredConfirmations,
  timingSafeEqualHex,
  upstashClaimStore,
  MAX_HEADER_BYTES,
} from "../dist/index.js";

const SECRET = "test_secret_at_least_16_chars_long";

/** Turn a plain header map into the lookup the codec expects. */
const get = (headers) => (name) => headers[name.toLowerCase()] ?? null;

const AUTH = {
  from: "0xPayer",
  to: "0xMerchant",
  value: "10000",
  validAfter: "0",
  validBefore: "9999999999",
  nonce: "abc123",
};

// ── amounts ───────────────────────────────────────────────────────────────

test("atomicAmount converts USD to 6-decimal atomic units", () => {
  assert.equal(atomicAmount(0.01), "10000");
  assert.equal(atomicAmount(1), "1000000");
  assert.equal(atomicAmount(0.000001), "1");
});

test("atomicAmount refuses non-positive and non-finite prices", () => {
  for (const bad of [0, -1, NaN, Infinity]) {
    assert.throws(() => atomicAmount(bad), RangeError);
  }
});

test("confirmation depth scales with value at risk", () => {
  assert.equal(requiredConfirmations(atomicAmount(0.01)), 3);
  assert.equal(requiredConfirmations(atomicAmount(5)), 6);
  assert.equal(requiredConfirmations(atomicAmount(100)), 12);
  assert.equal(requiredConfirmations("not-a-number"), 12, "unparseable must demand the STRONGEST gate");
});

// ── binding ───────────────────────────────────────────────────────────────

test("binding MAC is unique per resource, amount, quote, expiry and method", () => {
  const base = {
    method: "GET",
    resource: "https://x.dev/a",
    amount: "10000",
    quoteId: "q1",
    expiresAt: 1800000000,
  };
  const ref = bindingMac(SECRET, base);
  assert.notEqual(ref, bindingMac(SECRET, { ...base, resource: "https://x.dev/b" }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, amount: "20000" }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, quoteId: "q2" }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, expiresAt: 1800000001 }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, method: "POST" }));
  assert.notEqual(ref, bindingMac("a_different_secret_16", base), "forgeable only with the secret");
});

test("the MAC is version-independent — one binding serves v1 and v2", () => {
  // v1 and v2 carry the quote in `extra` alike, so the same MAC validates both.
  // This is also byte-identical to apps/web/src/lib/x402.ts. Changing this
  // formula breaks cross-compatibility with FurlPay's own priced resources.
  const mac = bindingMac(SECRET, {
    method: "GET",
    resource: "https://x.dev/a",
    amount: "10000",
    quoteId: "q1",
    expiresAt: 1800000000,
  });
  assert.equal(mac, bindingMac(SECRET, {
    method: "GET",
    resource: "https://x.dev/a",
    amount: "10000",
    quoteId: "q1",
    expiresAt: 1800000000,
  }));
});

test("body hash enters the MAC only when present", () => {
  const input = { method: "POST", resource: "https://x.dev/a", amount: "10000", quoteId: "q1", expiresAt: 1800000000 };
  const none = bindingMac(SECRET, input);
  const small = bindingMac(SECRET, { ...input, bodyHash: hashBody('{"model":"small"}') });
  const large = bindingMac(SECRET, { ...input, bodyHash: hashBody('{"model":"large"}') });

  assert.notEqual(none, small);
  assert.notEqual(small, large);
});

test("timingSafeEqualHex handles length mismatch without throwing", () => {
  assert.equal(timingSafeEqualHex("abcd", "abcd"), true);
  assert.equal(timingSafeEqualHex("abcd", "abce"), false);
  assert.equal(timingSafeEqualHex("abcd", "abcdef"), false);
});

// ── version negotiation ───────────────────────────────────────────────────

test("detectVersion reads the dialect off the header name", () => {
  assert.equal(detectVersion(get({ "payment-signature": "x" })), 2);
  assert.equal(detectVersion(get({ "x-payment": "x" })), 1);
  assert.equal(detectVersion(get({})), null);
  // v2 wins when a confused client sends both.
  assert.equal(detectVersion(get({ "x-payment": "x", "payment-signature": "y" })), 2);
});

test("decodePayment normalizes v1 and v2 to one shape", () => {
  const extra = { name: "USD Coin", version: "2", quoteId: "q1", expiresAt: 1800000000, binding: "deadbeef" };

  const v1 = decodePayment(
    get({
      "x-payment": b64encode({
        x402Version: 1,
        scheme: "exact",
        network: "base",
        payload: { signature: "0xab", authorization: AUTH },
        extra,
      }),
    })
  );
  const v2 = decodePayment(
    get({
      "payment-signature": b64encode({
        x402Version: 2,
        accepted: {
          scheme: "exact",
          network: "base",
          asset: "0xUSDC",
          amount: "10000",
          payTo: "0xMerchant",
          maxTimeoutSeconds: 300,
          extra,
        },
        payload: { signature: "0xab", authorization: AUTH },
      }),
    })
  );

  assert.equal(v1.ok, true);
  assert.equal(v2.ok, true);

  // Different wires, identical normalized view — which is why the gate is
  // written once and cannot drift between dialects.
  for (const [d, version] of [
    [v1, 1],
    [v2, 2],
  ]) {
    assert.equal(d.payment.version, version);
    assert.equal(d.payment.scheme, "exact");
    assert.equal(d.payment.network, "base");
    assert.equal(d.payment.quoteId, "q1");
    assert.equal(d.payment.binding, "deadbeef");
    assert.equal(d.payment.expiresAt, 1800000000);
    assert.equal(d.payment.authorization.from, "0xPayer");
  }
});

test("decodePayment rejects every malformed shape", () => {
  assert.equal(decodePayment(get({})).ok, false, "no header");
  assert.equal(decodePayment(get({ "x-payment": "!!!" })).ok, false, "not base64 json");
  assert.equal(decodePayment(get({ "payment-signature": "x".repeat(MAX_HEADER_BYTES + 1) })).ok, false, "oversized");

  // Wrong version number for the header it arrived on.
  assert.equal(decodePayment(get({ "x-payment": b64encode({ x402Version: 2 }) })).ok, false);
  assert.equal(decodePayment(get({ "payment-signature": b64encode({ x402Version: 1 }) })).ok, false);

  // v2 without `accepted` has nowhere to carry the quote.
  assert.equal(
    decodePayment(
      get({ "payment-signature": b64encode({ x402Version: 2, payload: { signature: "0xab", authorization: AUTH } }) })
    ).ok,
    false
  );

  // Authorization missing required EIP-3009 fields.
  assert.equal(
    decodePayment(
      get({
        "x-payment": b64encode({
          x402Version: 1,
          scheme: "exact",
          network: "base",
          payload: { signature: "0xab", authorization: { from: "0x1", to: "0x2", value: "1" } },
        }),
      })
    ).ok,
    false
  );
});

// ── receipts ──────────────────────────────────────────────────────────────

test("receipts encode per dialect and round-trip", () => {
  const receipt = {
    payer: "0xPayer",
    transaction: "0xdeadbeef",
    network: "base",
    asset: "0xUSDC",
    amountAtomic: "10000",
    resource: "https://x.dev/a",
    settledAt: new Date().toISOString(),
  };

  assert.deepEqual(decodeReceipt(encodeReceiptV1(receipt)), receipt);

  // v2 speaks the reference SDK's SettleResponse shape.
  const v2 = decodeReceipt(encodeReceiptV2(receipt));
  assert.equal(v2.success, true);
  assert.equal(v2.transaction, "0xdeadbeef");
  assert.equal(v2.amount, "10000");
  assert.equal(v2.payer, "0xPayer");

  assert.equal(decodeReceipt("not base64 json"), null);
});

// ── durable claim store ───────────────────────────────────────────────────

test("upstashClaimStore refuses to start without credentials", () => {
  // Silently degrading to in-memory would look durable and not be — the worst
  // possible failure mode for replay protection.
  assert.throws(() => upstashClaimStore({ url: "", token: "" }), /UPSTASH_REDIS_REST_URL/);
});

test("upstashClaimStore issues an atomic SET NX and reads the result", async () => {
  const calls = [];
  const store = upstashClaimStore({
    url: "https://fake.upstash.io",
    token: "tok",
    fetchImpl: async (_url, init) => {
      const cmd = JSON.parse(init.body);
      calls.push(cmd);
      // First claim wins ("OK"); a replay of the same key gets null.
      const seen = calls.filter((c) => c[1] === cmd[1]).length > 1;
      return { ok: true, json: async () => ({ result: seen ? null : "OK" }) };
    },
  });

  assert.equal(store.isDurable, true);
  assert.equal(await store.claim("x402:nonce:abc", 3600), true);
  assert.equal(await store.claim("x402:nonce:abc", 3600), false, "a replayed nonce must lose the claim");

  assert.deepEqual(calls[0], ["SET", "x402:nonce:abc", "1", "NX", "EX", "3600"]);
});

test("a claim store that errors fails closed", async () => {
  const store = claimStoreFrom(async () => {
    throw new Error("redis down");
  });
  assert.equal(await store.claim("k", 60), false, "a store we cannot reach cannot prove single-use");
});

test("an Upstash non-2xx fails closed", async () => {
  const store = upstashClaimStore({
    url: "https://fake.upstash.io",
    token: "tok",
    fetchImpl: async () => ({ ok: false, json: async () => ({}) }),
  });
  assert.equal(await store.claim("k", 60), false);
});

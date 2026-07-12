import test from "node:test";
import assert from "node:assert/strict";
import {
  atomicAmount,
  bindingMac,
  decodePaymentHeader,
  decodeReceipt,
  encodeReceipt,
  hashBody,
  requiredConfirmations,
  timingSafeEqualHex,
  MAX_HEADER_BYTES,
} from "../dist/index.js";

const SECRET = "test_secret_at_least_16_chars_long";

test("atomicAmount converts USD to 6-decimal atomic units", () => {
  assert.equal(atomicAmount(0.01), "10000");
  assert.equal(atomicAmount(1), "1000000");
  assert.equal(atomicAmount(0.000001), "1");
  assert.equal(atomicAmount(2.5), "2500000");
});

test("atomicAmount refuses non-positive and non-finite prices", () => {
  assert.throws(() => atomicAmount(0), RangeError);
  assert.throws(() => atomicAmount(-1), RangeError);
  assert.throws(() => atomicAmount(NaN), RangeError);
  assert.throws(() => atomicAmount(Infinity), RangeError);
});

test("confirmation depth scales with value at risk", () => {
  assert.equal(requiredConfirmations(atomicAmount(0.01)), 3);
  assert.equal(requiredConfirmations(atomicAmount(5)), 6);
  assert.equal(requiredConfirmations(atomicAmount(100)), 12);
  // Unparseable amount must demand the STRONGEST gate, not the weakest.
  assert.equal(requiredConfirmations("not-a-number"), 12);
});

test("binding MAC is unique per resource", () => {
  const base = { method: "GET", amount: "10000", quoteId: "q1", expiresAt: 1800000000 };
  const cheap = bindingMac(SECRET, { ...base, resource: "https://x.dev/cheap" });
  const dear = bindingMac(SECRET, { ...base, resource: "https://x.dev/expensive" });
  assert.notEqual(cheap, dear);
});

test("binding MAC is unique per amount, quote, and expiry", () => {
  const base = { method: "GET", resource: "https://x.dev/a", amount: "10000", quoteId: "q1", expiresAt: 1800000000 };
  const ref = bindingMac(SECRET, base);
  assert.notEqual(ref, bindingMac(SECRET, { ...base, amount: "20000" }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, quoteId: "q2" }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, expiresAt: 1800000001 }));
  assert.notEqual(ref, bindingMac(SECRET, { ...base, method: "POST" }));
});

test("binding MAC is forgeable only with the secret", () => {
  const input = { method: "GET", resource: "https://x.dev/a", amount: "10000", quoteId: "q1", expiresAt: 1800000000 };
  assert.notEqual(bindingMac(SECRET, input), bindingMac("a_different_secret_16", input));
});

test("body hash enters the MAC only when present, preserving wire compatibility", () => {
  const input = { method: "POST", resource: "https://x.dev/a", amount: "10000", quoteId: "q1", expiresAt: 1800000000 };
  const withoutBody = bindingMac(SECRET, input);
  const withBody = bindingMac(SECRET, { ...input, bodyHash: hashBody('{"model":"small"}') });
  assert.notEqual(withoutBody, withBody);

  // Different bodies must not share a MAC.
  const small = bindingMac(SECRET, { ...input, bodyHash: hashBody('{"model":"small"}') });
  const large = bindingMac(SECRET, { ...input, bodyHash: hashBody('{"model":"large"}') });
  assert.notEqual(small, large);
});

test("timingSafeEqualHex compares without throwing on length mismatch", () => {
  assert.equal(timingSafeEqualHex("abcd", "abcd"), true);
  assert.equal(timingSafeEqualHex("abcd", "abce"), false);
  assert.equal(timingSafeEqualHex("abcd", "abcdef"), false);
  assert.equal(timingSafeEqualHex("", ""), true);
});

test("decodePaymentHeader rejects every malformed shape", () => {
  assert.equal(decodePaymentHeader(null).ok, false);
  assert.equal(decodePaymentHeader("").ok, false);
  assert.equal(decodePaymentHeader("!!!not-base64!!!").ok, false);
  assert.equal(decodePaymentHeader("x".repeat(MAX_HEADER_BYTES + 1)).ok, false);

  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
  assert.equal(decodePaymentHeader(b64({ x402Version: 99 })).ok, false, "wrong version");
  assert.equal(decodePaymentHeader(b64({ x402Version: 1 })).ok, false, "no payload");
  assert.equal(
    decodePaymentHeader(b64({ x402Version: 1, payload: { signature: "0xab" } })).ok,
    false,
    "no authorization"
  );
  assert.equal(
    decodePaymentHeader(
      b64({
        x402Version: 1,
        payload: { signature: "0xab", authorization: { from: "0x1", to: "0x2", value: "1" } },
      })
    ).ok,
    false,
    "authorization missing validAfter/validBefore/nonce"
  );
});

test("decodePaymentHeader accepts a well-formed payload", () => {
  const header = Buffer.from(
    JSON.stringify({
      x402Version: 1,
      scheme: "exact",
      network: "base",
      payload: {
        signature: "0x" + "ab".repeat(65),
        authorization: {
          from: "0xPayer",
          to: "0xMerchant",
          value: "10000",
          validAfter: "0",
          validBefore: "9999999999",
          nonce: "abc123",
        },
      },
    })
  ).toString("base64");

  const decoded = decodePaymentHeader(header);
  assert.equal(decoded.ok, true);
  assert.equal(decoded.payload.payload.authorization.from, "0xPayer");
});

test("receipts round-trip", () => {
  const receipt = {
    payer: "0xPayer",
    transaction: "0xdeadbeef",
    network: "base",
    asset: "0xUSDC",
    amountAtomic: "10000",
    resource: "https://x.dev/a",
    settledAt: new Date().toISOString(),
  };
  assert.deepEqual(decodeReceipt(encodeReceipt(receipt)), receipt);
  assert.equal(decodeReceipt("not base64 json"), null);
});

// Regression test for the trailing-slash normaliser (js/polynomial-redos).
//
// Two things are asserted, and both matter: the linear form must be EXACTLY
// equivalent to the regex it replaced, and it must not degrade on the input
// that made the regex quadratic. An equivalence test alone would let a
// "fix" through that is still slow; a timing test alone would let one
// through that is fast and wrong.

import test from "node:test";
import assert from "node:assert/strict";
import { stripTrailingSlashes } from "../dist/protocol.js";

const REGEX = /\/+$/;

test("matches the regex it replaced on hand-picked cases", () => {
  const cases = [
    "", "/", "//", "///", "a", "a/", "a//", "a///",
    "https://x.com", "https://x.com/", "https://x.com///",
    "/leading", "//leading", "mid/dle", "mid/dle//",
    "/".repeat(64), "x" + "/".repeat(64),
  ];
  for (const s of cases) {
    assert.equal(stripTrailingSlashes(s), s.replace(REGEX, ""), `mismatch on ${JSON.stringify(s)}`);
  }
});

test("matches the regex across randomised inputs", () => {
  // Deterministic seed so a CI failure is reproducible.
  let seed = 42;
  const rnd = (n) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n);
  for (let i = 0; i < 2000; i++) {
    const len = rnd(40);
    let s = "";
    for (let j = 0; j < len; j++) s += "ab/".charAt(rnd(3));
    assert.equal(stripTrailingSlashes(s), s.replace(REGEX, ""));
  }
});

test("stays linear on the input that made the regex quadratic", () => {
  // 200k slashes followed by a non-slash: the regex retries from every offset.
  // The old form took ~1.1s at 40k and scales quadratically from there.
  const pathological = "/".repeat(200_000) + "x";
  const started = process.hrtime.bigint();
  const out = stripTrailingSlashes(pathological);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(out, pathological, "no trailing slash, so nothing should be stripped");
  // Generous bound: the measured cost is ~0.06ms. Anything approaching the
  // regex's behaviour would be orders of magnitude over this.
  assert.ok(ms < 50, `took ${ms.toFixed(2)}ms — expected linear behaviour`);
});

test("strips a long genuine run of trailing slashes", () => {
  const s = "https://facilitator.example" + "/".repeat(100_000);
  assert.equal(stripTrailingSlashes(s), "https://facilitator.example");
});

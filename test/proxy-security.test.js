import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import { createProxy } from "../dist/adapters/proxy.js";
import { canonicalizeTarget, compileFreePaths } from "../dist/index.js";

// ---------------------------------------------------------------------------
// Reverse-proxy path security. The origin here decodes and normalizes the way
// python http.server / serve-static / a Windows-backed server do — the shape
// that turned `/docs%2f..%2fsecret` into a free paid resource (report 117).
// Every attack asserts two things: no paid bytes came back, and the origin's
// paid handler was never reached.
// ---------------------------------------------------------------------------

const SECRET = "test_secret_at_least_16_chars_long";
const PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const PAYER = "0xAbC0000000000000000000000000000000000001";
const PAID = "PAID-SECRET-CONTENT-42";

const FILES = {
  "docs/readme.txt": "public-doc",
  "docs/café.txt": "public-unicode",
  "secret/data.txt": PAID,
  expensive: "EXPENSIVE-CONTENT",
};

function startOrigin() {
  const hits = [];
  const server = http.createServer((req, res) => {
    let p;
    try {
      p = decodeURIComponent(req.url.split("?")[0]);
    } catch {
      res.writeHead(400).end();
      return;
    }
    p = path.posix.normalize(p.replace(/\\/g, "/")).replace(/^\/+/, "");
    hits.push(p);
    if (p === "docs/go") {
      res.writeHead(302, { location: "/secret/data.txt" }).end();
      return;
    }
    const body = FILES[p];
    if (body === undefined) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": "text/plain" }).end(body);
  });
  return { server, hits };
}

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));

function okFacilitator() {
  return {
    async verify() {
      return { isValid: true, payer: PAYER };
    },
    async settle(req) {
      return { success: true, transaction: "0x" + "de".repeat(32), network: req.paymentRequirements.network, payer: PAYER, confirmations: 12 };
    },
    async supported() {
      return [];
    },
  };
}

async function setup(opts = {}) {
  const origin = startOrigin();
  const originPort = await listen(origin.server);
  const proxy = createProxy({
    origin: `http://127.0.0.1:${originPort}`,
    price: (ctx) => (ctx.url.pathname === "/expensive" ? 2.0 : 0.01),
    payTo: PAY_TO,
    quoteSecret: SECRET,
    network: "base",
    freePaths: ["/docs*", "/health"],
    facilitator: okFacilitator(),
    ...opts,
  });
  const port = await listen(proxy);
  return {
    port,
    hits: origin.hits,
    paidHits: () => origin.hits.filter((h) => h.startsWith("secret") || h === "expensive"),
    close: () => Promise.all([new Promise((r) => proxy.close(r)), new Promise((r) => origin.server.close(r))]),
  };
}

/** Send the target byte-for-byte; fetch() would normalize it first. */
function raw(port, target, { method = "GET", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: target, headers }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

/** Pay a 402 as a v1 client would. */
function payV1(challengeBody) {
  const req = JSON.parse(challengeBody).accepts[0];
  const payload = {
    x402Version: 1,
    scheme: "exact",
    network: req.network,
    payload: {
      signature: "0x" + "ab".repeat(65),
      authorization: {
        from: PAYER,
        to: PAY_TO,
        value: req.maxAmountRequired,
        validAfter: "0",
        validBefore: String(Math.floor(Date.now() / 1000) + 600),
        nonce: crypto.randomBytes(32).toString("hex"),
      },
    },
    extra: req.extra,
  };
  return { "x-payment": Buffer.from(JSON.stringify(payload)).toString("base64") };
}

// ── the report's proof of concept ─────────────────────────────────────────

test("report 117 PoC: free doc 200, paid 402, encoded traversal never leaks", async () => {
  const p = await setup();
  try {
    const free = await raw(p.port, "/docs/readme.txt");
    assert.equal(free.status, 200);
    assert.equal(free.body, "public-doc");

    const paid = await raw(p.port, "/secret/data.txt");
    assert.equal(paid.status, 402);

    const attack = await raw(p.port, "/docs%2f..%2fsecret/data.txt");
    assert.notEqual(attack.status, 200);
    assert.ok(!attack.body.includes(PAID), "paid content leaked");
    assert.deepEqual(p.paidHits(), [], "origin's paid resource was reached");
  } finally {
    await p.close();
  }
});

// ── attack matrix ─────────────────────────────────────────────────────────

const ATTACKS = [
  "/docs%2f..%2fsecret/data.txt",
  "/docs%2F..%2Fsecret/data.txt",
  "/docs%2f%2e%2e%2fsecret/data.txt",
  "/docs/%2e%2e/secret/data.txt",
  "/docs/%2E%2e/secret/data.txt",
  "/docs/.%2e/secret/data.txt",
  "/docs/%2e./secret/data.txt",
  "/docs/../secret/data.txt",
  "/docs/./../secret/data.txt",
  "/docs%5c..%5csecret/data.txt",
  "/docs%5C..%5Csecret/data.txt",
  "/docs\\..\\secret/data.txt",
  "/docs/..\\secret/data.txt",
  "/docs%252f..%252fsecret/data.txt",
  "/docs%25252f..%25252fsecret/data.txt",
  "/docs/%252e%252e/secret/data.txt",
  "/docs/..;/secret/data.txt",
  "/docs/..%3b/secret/data.txt",
  "/docs/%EF%BC%8F..%EF%BC%8Fsecret/data.txt", // U+FF0F fullwidth solidus
  "/docs/%E2%80%A5/secret/data.txt", // U+2025 two-dot leader -> ".." under NFKC
  "/docs/%C0%AE%C0%AE/secret/data.txt", // overlong UTF-8 "."
  "/docs/%2/secret/data.txt",
  "/docs/%zz/secret/data.txt",
  "/docs/%00/../secret/data.txt",
  "/docs//../secret/data.txt",
  "//docs/../secret/data.txt",
  "http://127.0.0.1/docs/../secret/data.txt",
];

for (const target of ATTACKS) {
  test(`attack ${target}: no paid content, origin not reached`, async () => {
    const p = await setup();
    try {
      const r = await raw(p.port, target);
      assert.ok(r.status === 400 || r.status === 402, `expected 400/402, got ${r.status}`);
      assert.ok(!r.body.includes(PAID), "paid content leaked");
      assert.deepEqual(p.paidHits(), [], "origin's paid resource was reached");
    } catch (e) {
      // node:http may refuse to even send some malformed targets; that is a
      // client-side refusal, not a bypass.
      if (e.code === "ERR_UNESCAPED_CHARACTERS") return;
      throw e;
    } finally {
      await p.close();
    }
  });
}

// ── legitimate traffic still works ────────────────────────────────────────

test("free paths: exact, prefix, unicode, encoded unreserved, trailing slash", async () => {
  const p = await setup();
  try {
    assert.equal((await raw(p.port, "/docs/readme.txt")).body, "public-doc");
    assert.equal((await raw(p.port, "/docs/caf%C3%A9.txt")).body, "public-unicode");
    assert.equal((await raw(p.port, "/docs/caf%c3%a9.txt")).body, "public-unicode");
    assert.equal((await raw(p.port, "/d%6fcs/readme.txt")).body, "public-doc");
    assert.equal((await raw(p.port, "/docs/readme.txt?v=1&x=a%2Fb")).body, "public-doc");
    assert.equal((await raw(p.port, "/health")).status, 404); // free, origin has no such file
  } finally {
    await p.close();
  }
});

test("a paid request with a valid payment is forwarded and served", async () => {
  const p = await setup();
  try {
    const c = await raw(p.port, "/secret/data.txt?fmt=txt");
    assert.equal(c.status, 402);
    assert.deepEqual(p.paidHits(), [], "402 must not touch the origin");

    const r = await raw(p.port, "/secret/data.txt?fmt=txt", { headers: payV1(c.body) });
    assert.equal(r.status, 200);
    assert.equal(r.body, PAID);
    assert.ok(r.headers["x-payment-response"], "receipt header missing");
    assert.match(r.headers["cache-control"], /no-store/);
  } finally {
    await p.close();
  }
});

test("a query string does not change the free/paid decision", async () => {
  const p = await setup();
  try {
    const r = await raw(p.port, "/secret/data.txt?path=/docs/readme.txt");
    assert.equal(r.status, 402);
    assert.deepEqual(p.paidHits(), []);
  } finally {
    await p.close();
  }
});

// ── resource identity ─────────────────────────────────────────────────────

test("an encoded alias of a priced path is quoted at that path's price", async () => {
  // Before: price(ctx) saw "/exp%65nsive", missed the "/expensive" rule, quoted
  // $0.01 — and a decoding origin served /expensive.
  const p = await setup();
  try {
    const c = await raw(p.port, "/exp%65nsive");
    assert.equal(c.status, 402);
    const req = JSON.parse(c.body).accepts[0];
    assert.equal(req.maxAmountRequired, "2000000");
    assert.match(req.resource, /\/expensive$/);
  } finally {
    await p.close();
  }
});

test("aliases share one identity: a quote for one spelling is the same resource", async () => {
  const p = await setup();
  try {
    const c = await raw(p.port, "/s%65cret/data.txt");
    const headers = payV1(c.body);
    const r = await raw(p.port, "/secret/data.txt", { headers });
    assert.equal(r.status, 200);
    // ...and that one payment cannot be spent again through another spelling.
    const again = await raw(p.port, "/s%65cret/data.txt", { headers });
    assert.equal(again.status, 402);
    assert.match(again.body, /already used|replay/i);
  } finally {
    await p.close();
  }
});

test("a payment for one resource cannot unlock another through the proxy", async () => {
  const p = await setup({ price: 0.01 });
  try {
    const c = await raw(p.port, "/secret/other.txt");
    const r = await raw(p.port, "/secret/data.txt", { headers: payV1(c.body) });
    assert.equal(r.status, 402);
    assert.match(r.body, /binding mismatch/i);
    assert.deepEqual(p.paidHits(), []);
  } finally {
    await p.close();
  }
});

// ── lifecycle failures fail closed ────────────────────────────────────────

test("a redirect from a free path is passed to the client, not followed", async () => {
  const p = await setup();
  try {
    const r = await raw(p.port, "/docs/go");
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, "/secret/data.txt");
    assert.ok(!r.body.includes(PAID));
    assert.deepEqual(p.paidHits(), [], "proxy followed the redirect to a paid resource");
  } finally {
    await p.close();
  }
});

test("a throwing facilitator is a 503 and never reaches the origin", async () => {
  const boom = { async verify() { throw new Error("down"); }, async settle() { throw new Error("down"); }, async supported() { return []; } };
  const p = await setup({ facilitator: boom });
  try {
    const c = await raw(p.port, "/secret/data.txt");
    const r = await raw(p.port, "/secret/data.txt", { headers: payV1(c.body) });
    assert.equal(r.status, 503);
    assert.ok(!r.body.includes(PAID));
    assert.deepEqual(p.paidHits(), []);
  } finally {
    await p.close();
  }
});

test("a failed verification never falls back to free access", async () => {
  const bad = { async verify() { return { isValid: false, invalidReason: "bad_sig" }; }, async settle() { return { success: false, errorReason: "bad_sig" }; }, async supported() { return []; } };
  const p = await setup({ facilitator: bad });
  try {
    const c = await raw(p.port, "/secret/data.txt");
    const r = await raw(p.port, "/secret/data.txt", { headers: payV1(c.body) });
    assert.equal(r.status, 402);
    assert.deepEqual(p.paidHits(), []);
  } finally {
    await p.close();
  }
});

test("a malformed Host header is refused when no publicUrl is set", async () => {
  const p = await setup();
  try {
    const r = await raw(p.port, "/secret/data.txt", { headers: { host: "evil.com/docs" } });
    assert.equal(r.status, 400);
    assert.deepEqual(p.paidHits(), []);
  } finally {
    await p.close();
  }
});

// ── canonicalizer + freePaths units ───────────────────────────────────────

test("canonicalizeTarget normalizes only what is unambiguous", () => {
  const ok = (t) => {
    const c = canonicalizeTarget(t);
    assert.ok(c.ok, `${t} rejected: ${c.reason}`);
    return c.path + c.search;
  };
  assert.equal(ok("/"), "/");
  assert.equal(ok("/a/b/"), "/a/b/");
  assert.equal(ok("/exp%65nsive"), "/expensive");
  assert.equal(ok("/a%7eb"), "/a~b");
  assert.equal(ok("/caf%c3%a9"), "/caf%C3%A9");
  assert.equal(ok("/a%20b?q=%2F"), "/a%20b?q=%2F");
  assert.equal(ok("/100%25"), "/100%25");
  assert.equal(ok("/a;v=1/b"), "/a;v=1/b");
  assert.equal(ok("/.well-known/x"), "/.well-known/x");
  assert.equal(ok("/..."), "/...");

  for (const bad of ["", "*", "docs", "//x", "/a//b", "/a#f", "/a/%2e", "/a/%2E%2E/b", "/a%2Fb", "/a%5cb", "/a%25%32%46b", "/a%2541", "/%C3%28", "/%c0%ae%c0%ae", "/a\u0000"]) {
    assert.equal(canonicalizeTarget(bad).ok, false, `${JSON.stringify(bad)} should be rejected`);
  }
});

test("freePaths: patterns are canonicalized, invalid ones fail at startup", () => {
  const isFree = compileFreePaths(["/d%6fcs*", "/health", "/assets/*"]);
  assert.equal(isFree("/docs/x"), true);
  assert.equal(isFree("/health"), true);
  assert.equal(isFree("/healthz"), false, "exact patterns are exact");
  assert.equal(isFree("/assets/app.js"), true);
  assert.equal(isFree("/assets"), false, "segment-bounded prefix excludes the bare dir");
  assert.equal(isFree("/secret"), false);
  assert.equal(compileFreePaths(["*"])("/anything"), true, "'*' keeps meaning everything");

  assert.throws(() => compileFreePaths(["docs*"]), /invalid freePaths/);
  assert.throws(() => compileFreePaths(["/docs/../secret"]), /invalid freePaths/);
  assert.throws(() => compileFreePaths(["/a?b=1"]), /invalid freePaths/);
});

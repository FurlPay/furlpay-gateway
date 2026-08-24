import { stripTrailingSlashes } from "./protocol.js";
// ---------------------------------------------------------------------------
// Single-use claim store.
//
// Two tokens must be burned exactly once per payment: the EIP-3009 nonce (the
// money-level token) and the quoteId (the resource-level token). "Exactly once"
// has to hold ACROSS PROCESSES, which is the part that is easy to get wrong.
//
// The classic serverless bug: a `Set` in module scope looks like replay
// protection and passes every local test, because in dev there is one process.
// In production there are N lambdas, each with its own empty Set, so the same
// X-PAYMENT replayed N times clears N different Sets and grants the resource N
// times — one payment, N deliveries. The fix is an ATOMIC claim in shared state
// (Redis SET NX), which linearizes the burn across every instance.
//
// MemoryClaimStore is therefore correct on exactly one instance and is labelled
// as such. `isDurable` exists so a deployment can assert on it at boot rather
// than discover it in an incident.
// ---------------------------------------------------------------------------

export interface ClaimStore {
  /**
   * Atomically claim `key`. Returns true iff THIS caller is the first to claim
   * it. Must be a genuine compare-and-set — a get-then-set is a race, and the
   * race is the vulnerability.
   */
  claim(key: string, ttlSeconds: number): Promise<boolean>;
  /** False if claims are not shared across instances. */
  readonly isDurable: boolean;
}

/**
 * In-memory claim store. Single instance only.
 *
 * Bounded so a flood of distinct quoteIds cannot grow it without limit; eviction
 * is oldest-expiry-first, and expired entries are dropped lazily on access.
 */
export class MemoryClaimStore implements ClaimStore {
  readonly isDurable = false;
  private readonly entries = new Map<string, number>(); // key → expiry (ms)

  constructor(private readonly maxEntries = 100_000) {}

  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();
    const existing = this.entries.get(key);
    if (existing !== undefined && existing > now) return false; // already burned
    if (existing !== undefined) this.entries.delete(key); // expired → reclaimable

    if (this.entries.size >= this.maxEntries) this.evict(now);
    this.entries.set(key, now + ttlSeconds * 1000);
    return true;
  }

  private evict(now: number): void {
    for (const [k, expiry] of this.entries) {
      if (expiry <= now) this.entries.delete(k);
    }
    // Still full of live entries — drop the soonest-to-expire to stay bounded.
    if (this.entries.size >= this.maxEntries) {
      const oldest = [...this.entries.entries()].sort((a, b) => a[1] - b[1]);
      const drop = Math.ceil(this.maxEntries * 0.1);
      for (let i = 0; i < drop && i < oldest.length; i++) this.entries.delete(oldest[i][0]);
    }
  }

  /** Test/introspection helper. */
  get size(): number {
    return this.entries.size;
  }
}

/**
 * Wrap any atomic set-if-not-exists primitive as a ClaimStore, without this
 * package taking a Redis dependency.
 *
 * @example
 *   import { Redis } from "@upstash/redis";
 *   const redis = Redis.fromEnv();
 *   const store = claimStoreFrom(
 *     (key, ttl) => redis.set(key, 1, { nx: true, ex: ttl }).then((r) => r === "OK")
 *   );
 */
export function claimStoreFrom(
  setNx: (key: string, ttlSeconds: number) => Promise<boolean>,
  isDurable = true
): ClaimStore {
  return {
    isDurable,
    async claim(key, ttlSeconds) {
      try {
        return await setNx(key, ttlSeconds);
      } catch {
        // A claim store we cannot reach cannot prove single-use. Refusing the
        // payment loses a sale; granting it risks unbounded duplicate delivery
        // on a single authorization. Refuse.
        return false;
      }
    },
  };
}

export interface UpstashClaimStoreOptions {
  /** Upstash REST endpoint, e.g. https://eu2-xxx.upstash.io */
  url?: string;
  token?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * Durable claim store backed by Upstash Redis over its REST API.
 *
 * Uses `SET key value NX EX ttl`, which is a genuine atomic compare-and-set on
 * the Redis server — the burn is linearized across every instance, which is the
 * whole property that makes it safe on serverless. Reads `UPSTASH_REDIS_REST_URL`
 * and `UPSTASH_REDIS_REST_TOKEN` from the environment when not passed.
 *
 * Zero dependencies: it is one HTTP call, so it needs no Redis client library.
 *
 * @example
 *   import { paywall, upstashClaimStore } from "@furlpay/gateway";
 *   const pay = paywall({ price: 0.01, payTo, quoteSecret, claimStore: upstashClaimStore() });
 */
export function upstashClaimStore(opts: UpstashClaimStoreOptions = {}): ClaimStore {
  const url = stripTrailingSlashes(opts.url ?? process.env.UPSTASH_REDIS_REST_URL ?? "");
  const token = opts.token ?? process.env.UPSTASH_REDIS_REST_TOKEN ?? "";
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const doFetch = opts.fetchImpl ?? globalThis.fetch;

  if (!url || !token) {
    throw new Error(
      "@furlpay/gateway: upstashClaimStore() needs UPSTASH_REDIS_REST_URL and " +
        "UPSTASH_REDIS_REST_TOKEN (or explicit url/token). Refusing to start with " +
        "undurable replay protection that looks durable."
    );
  }

  return claimStoreFrom(async (key, ttlSeconds) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      // Pipeline-free single command: ["SET", key, "1", "NX", "EX", ttl]
      const res = await doFetch(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(["SET", key, "1", "NX", "EX", String(ttlSeconds)]),
        signal: ctl.signal,
      });
      if (!res.ok) return false; // fail closed
      const body = (await res.json()) as { result?: string | null };
      // Redis returns "OK" when the key was set, null when it already existed.
      return body?.result === "OK";
    } finally {
      clearTimeout(timer);
    }
  }, true);
}

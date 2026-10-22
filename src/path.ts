// ---------------------------------------------------------------------------
// Request-target canonicalization for the reverse proxy.
//
// The proxy makes a security decision (free or paid, and at what price) on a
// path, then hands that path to an origin it does not control. If the two read
// the path differently, the decision is about one resource and the response is
// another. That is exactly how `/docs%2f..%2fsecret` got past a `/docs*` free
// prefix: the gate saw one opaque segment under /docs, the origin decoded it
// into `/docs/../secret` and served /secret.
//
// So the rule here is: produce ONE canonical path, make every decision on it,
// and forward exactly it. Anything whose meaning could differ between this
// process and a plausible origin is refused, never repaired:
//
//   - encoded separators (%2F, %5C) and backslashes
//   - dot-segments in any spelling (., .., %2e, %2E%2e, ..;param, NFKC lookalikes)
//   - nested encoding (%25XX), which a double-decoding origin would expand
//   - malformed escapes and invalid UTF-8
//   - empty interior segments (//), which some origins collapse and some don't
//   - control characters, and targets that are not origin-form (/path)
//
// What remains decodes the same way everywhere, so it is normalized (RFC 3986
// §6.2.2): escapes of unreserved characters are decoded, other escapes are
// upper-cased. `/exp%65nsive` and `/expensive` are then one resource with one
// price, not two.
// ---------------------------------------------------------------------------

export type CanonicalTarget =
  | { ok: true; path: string; search: string }
  | { ok: false; reason: string };

const MAX_TARGET_LENGTH = 8192;

/** RFC 3986 pchar minus "/", raw form. "%" is validated separately. */
const SEGMENT_CHARS = /^[A-Za-z0-9\-._~!$&'()*+,;=:@%]*$/;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const HEX = /^[0-9A-Fa-f]{2}$/;
/** Printable ASCII only — clients percent-encode everything else. */
const QUERY_CHARS = /^[\x21-\x7e]*$/;

const fail = (reason: string): CanonicalTarget => ({ ok: false, reason });

/** Decode unreserved escapes, upper-case the rest. Null when an escape is malformed. */
function normalizeEscapes(segment: string): string | null {
  let out = "";
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (c !== "%") {
      out += c;
      continue;
    }
    const hex = segment.slice(i + 1, i + 3);
    if (!HEX.test(hex)) return null;
    const ch = String.fromCharCode(parseInt(hex, 16));
    out += UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
    i += 2;
  }
  return out;
}

function isDotSegment(s: string): boolean {
  // Servlet containers strip ";params" before resolving, so "..;x" is "..".
  const bare = s.split(";")[0];
  return bare === "." || bare === "..";
}

/** Why this already-normalized segment is ambiguous, or null if it is safe. */
function segmentHazard(segment: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    return "invalid percent-encoding or UTF-8 in path";
  }
  if (isDotSegment(decoded)) return "dot-segment in path";
  if (/[/\\]/.test(decoded)) return "encoded path separator";
  if (/[\x00-\x1f\x7f]/.test(decoded)) return "control character in path";
  if (/%[0-9A-Fa-f]{2}/.test(decoded)) return "nested percent-encoding in path";

  // Origins that apply Unicode compatibility normalization would turn
  // U+FF0F into "/" and U+2025 into "..".
  const folded = decoded.normalize("NFKC");
  if (isDotSegment(folded) || /[/\\]/.test(folded)) return "path separator or dot-segment after Unicode normalization";
  return null;
}

/**
 * Canonicalize a raw HTTP request-target (`req.url` from node:http).
 * Only origin-form is accepted; absolute-form and authority-form are refused.
 */
export function canonicalizeTarget(target: string | undefined): CanonicalTarget {
  if (typeof target !== "string" || target.length === 0) return fail("empty request target");
  if (target.length > MAX_TARGET_LENGTH) return fail("request target too long");
  if (target[0] !== "/") return fail("request target must be origin-form (start with '/')");
  if (target.startsWith("//")) return fail("empty path segment");
  if (target.includes("#")) return fail("fragment in request target");

  const q = target.indexOf("?");
  const rawPath = q === -1 ? target : target.slice(0, q);
  const search = q === -1 ? "" : target.slice(q);
  if (!QUERY_CHARS.test(search)) return fail("invalid character in query");

  const segments = rawPath.slice(1).split("/");
  const out: string[] = [];
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg === "") {
      // A trailing slash is meaningful and unambiguous; an interior one is not.
      if (i === segments.length - 1) {
        out.push("");
        continue;
      }
      return fail("empty path segment");
    }
    if (!SEGMENT_CHARS.test(seg)) return fail("invalid character in path");
    const norm = normalizeEscapes(seg);
    if (norm === null) return fail("malformed percent-encoding in path");
    const hazard = segmentHazard(norm);
    if (hazard) return fail(hazard);
    out.push(norm);
  }

  return { ok: true, path: "/" + out.join("/"), search };
}

/**
 * Compile `freePaths` patterns ("/health" exact, "/docs*" prefix) into a
 * matcher over canonical paths. Patterns are canonicalized with the same rules
 * as requests, so `/d%6fcs*` and `/docs*` mean the same thing, and an invalid
 * pattern is a startup error rather than a silently dead rule.
 *
 * Prefix patterns are plain string prefixes, as before: "/docs*" also matches
 * "/docs-internal". Write "/docs/*" to stop at the segment boundary.
 */
export function compileFreePaths(patterns: string[]): (path: string) => boolean {
  const compiled = patterns.map((raw) => {
    const prefix = raw.endsWith("*");
    const body = prefix ? raw.slice(0, -1) : raw;
    if (prefix && body === "") return { prefix, path: "" }; // "*": everything free
    const c = canonicalizeTarget(body);
    if (!c.ok || c.search) {
      throw new Error(`@furlpay/gateway: invalid freePaths entry "${raw}"${c.ok ? ": query not allowed" : `: ${c.reason}`}`);
    }
    return { prefix, path: c.path };
  });
  return (path) => compiled.some((p) => (p.prefix ? path.startsWith(p.path) : path === p.path));
}

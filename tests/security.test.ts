import { describe, expect, it } from "bun:test";
import {
  isOriginAllowed,
  normalizeOrigin,
  parseAllowedOrigins,
  createCorsOriginResolver,
  getSecurityHeaders,
  applySecurityHeaders,
  MINIMAL_SSR_CSP,
  RateLimiter,
  RATE_LIMIT_POLICIES,
  resolveClientIp,
} from "../src/server/security";

// ============================================================================
// 1. Origin Parsing & CORS Allowlist
// ============================================================================

describe("Origin Parsing & CORS Allowlist", () => {
  it("normalizes origin URLs correctly", () => {
    expect(normalizeOrigin("https://usemeter.com/")).toBe("https://usemeter.com");
    expect(normalizeOrigin("HTTP://LOCALHOST:3000///")).toBe("http://localhost:3000");
    expect(normalizeOrigin("   https://App.Example.com:8443   ")).toBe("https://app.example.com:8443");
    expect(normalizeOrigin("")).toBeNull();
    expect(normalizeOrigin("null")).toBeNull();
    expect(normalizeOrigin(null)).toBeNull();
    expect(normalizeOrigin(undefined)).toBeNull();
  });

  it("parses empty origin configs as same-origin only", () => {
    // With requestOrigin provided
    const withReq = parseAllowedOrigins(undefined, "https://usemeter.com");
    expect(withReq).toEqual(["https://usemeter.com"]);

    const withEmptyStr = parseAllowedOrigins("", "https://usemeter.com");
    expect(withEmptyStr).toEqual(["https://usemeter.com"]);

    // Without requestOrigin
    const withoutReq = parseAllowedOrigins(undefined, null);
    expect(withoutReq).toEqual([]);
  });

  it("parses wildcard and multi-origin configs", () => {
    expect(parseAllowedOrigins("*")).toBe("*");
    expect(parseAllowedOrigins("https://a.com, https://b.com/")).toEqual([
      "https://a.com",
      "https://b.com",
    ]);
    expect(parseAllowedOrigins(["https://a.com", "https://b.com:8080"])).toEqual([
      "https://a.com",
      "https://b.com:8080",
    ]);
    expect(parseAllowedOrigins("https://a.com, *")).toBe("*");
  });

  it("rejects cross-origin requests when allowlist is empty (same-origin enforcement)", () => {
    expect(
      isOriginAllowed("https://attacker.com", {
        allowedOrigins: undefined,
        requestOrigin: "https://usemeter.com",
      })
    ).toBe(false);

    expect(
      isOriginAllowed("https://usemeter.com", {
        allowedOrigins: undefined,
        requestOrigin: "https://usemeter.com",
      })
    ).toBe(true);

    expect(
      isOriginAllowed("https://usemeter.com", {
        allowedOrigins: "",
        requestOrigin: null,
      })
    ).toBe(false);
  });

  it("strictly forbids wildcard * when credentials are permitted", () => {
    // Explicit wildcard with credentials: MUST reject
    expect(
      isOriginAllowed("https://attacker.com", {
        allowedOrigins: "*",
        allowCredentials: true,
      })
    ).toBe(false);

    expect(
      isOriginAllowed("https://friendly.com", {
        allowedOrigins: "*",
        allowCredentials: true,
      })
    ).toBe(false);

    // Wildcard without credentials: permitted
    expect(
      isOriginAllowed("https://friendly.com", {
        allowedOrigins: "*",
        allowCredentials: false,
      })
    ).toBe(true);
  });

  it("prevents prefix, suffix, and subdomain hijacking in allowlist matching", () => {
    const options = {
      allowedOrigins: "https://example.com",
      requestOrigin: "https://example.com",
    };

    expect(isOriginAllowed("https://example.com", options)).toBe(true);
    expect(isOriginAllowed("https://example.com.attacker.com", options)).toBe(false);
    expect(isOriginAllowed("https://attacker-example.com", options)).toBe(false);
    expect(isOriginAllowed("https://sub.example.com", options)).toBe(false);
    expect(isOriginAllowed("http://example.com", options)).toBe(false); // protocol mismatch
    expect(isOriginAllowed("https://example.com:8443", options)).toBe(false); // port mismatch
    expect(isOriginAllowed("null", options)).toBe(false);
  });

  it("creates a CORS origin resolver suitable for Hono middleware", () => {
    const resolver = createCorsOriginResolver({
      allowedOrigins: "https://trusted.com",
      defaultRequestOrigin: "https://usemeter.com",
      allowCredentials: true,
    });

    // Allowed origin is reflected
    expect(resolver("https://trusted.com")).toBe("https://trusted.com");

    // Same-origin via request context URL is reflected
    expect(
      resolver("https://app.usemeter.com", {
        req: { url: "https://app.usemeter.com/api/poll" },
      })
    ).toBe("https://app.usemeter.com");

    // Rejected origin returns null
    expect(resolver("https://evil.com")).toBeNull();

    // Wildcard without credentials returns "*"
    const publicResolver = createCorsOriginResolver({
      allowedOrigins: "*",
      allowCredentials: false,
    });
    expect(publicResolver("https://any-client.org")).toBe("*");
  });
});

// ============================================================================
// 2. Security Headers & CSP
// ============================================================================

describe("Security Headers & CSP", () => {
  it("includes all required security headers for insecure (HTTP/dev) requests without HSTS", () => {
    const headers = getSecurityHeaders(false);

    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["Permissions-Policy"]).toContain("camera=()");
    expect(headers["Content-Security-Policy"]).toBe(MINIMAL_SSR_CSP);
    expect(headers["Strict-Transport-Security"]).toBeUndefined();
  });

  it("includes HSTS only when secure parameter is true", () => {
    const headers = getSecurityHeaders(true);
    expect(headers["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");

    // Explicit override
    const customHsts = getSecurityHeaders(true, { hstsMaxAge: 86400 });
    expect(customHsts["Strict-Transport-Security"]).toBe("max-age=86400; includeSubDomains");

    const disabledHsts = getSecurityHeaders(true, { hsts: false });
    expect(disabledHsts["Strict-Transport-Security"]).toBeUndefined();
  });

  it("ensures CSP permits inline scripts/styles and Tailwind CDN for SSR", () => {
    expect(MINIMAL_SSR_CSP).toContain("script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com");
    expect(MINIMAL_SSR_CSP).toContain("style-src 'self' 'unsafe-inline'");
    expect(MINIMAL_SSR_CSP).toContain("frame-ancestors 'none'");
    expect(MINIMAL_SSR_CSP).toContain("base-uri 'self'");
    expect(MINIMAL_SSR_CSP).toContain("form-action 'self'");
  });

  it("applies headers to both standard Headers objects and plain Records", () => {
    // 1. Plain record
    const record: Record<string, string> = { "X-Custom": "1" };
    applySecurityHeaders(record, false);
    expect(record["X-Content-Type-Options"]).toBe("nosniff");
    expect(record["X-Custom"]).toBe("1");

    // 2. Web standard Headers object
    const webHeaders = new Headers({ "X-Existing": "test" });
    applySecurityHeaders(webHeaders, true);
    expect(webHeaders.get("X-Content-Type-Options")).toBe("nosniff");
    expect(webHeaders.get("Strict-Transport-Security")).toBe("max-age=31536000; includeSubDomains");
    expect(webHeaders.get("X-Existing")).toBe("test");
  });
});

// ============================================================================
// 3. Bounded In-Memory RateLimiter
// ============================================================================

describe("Bounded In-Memory RateLimiter", () => {
  it("enforces rate limit boundaries with deterministic clock seam", () => {
    let nowTime = 1_000_000;
    const limiter = new RateLimiter({ now: () => nowTime });
    const policy = { max: 3, windowMs: 10_000 };

    // Request 1
    const r1 = limiter.check("ip-1", policy);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(2);
    expect(r1.total).toBe(3);
    expect(r1.retryAfterSec).toBeUndefined();

    // Request 2 (2 seconds later)
    nowTime += 2000;
    const r2 = limiter.check("ip-1", policy);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(1);

    // Request 3 (3 seconds later)
    nowTime += 3000;
    const r3 = limiter.check("ip-1", policy);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);

    // Request 4 (1 second later -> 6s since start, limit exhausted)
    nowTime += 1000;
    const r4 = limiter.check("ip-1", policy);
    expect(r4.allowed).toBe(false);
    expect(r4.remaining).toBe(0);
    // Oldest was at 1_000_000, expires at 1_010_000. Now is 1_006_000.
    // resetMs = 4000, retryAfterSec = 4
    expect(r4.resetMs).toBe(4000);
    expect(r4.retryAfterSec).toBe(4);

    // Advance past oldest request (now is 1_011_000)
    nowTime = 1_011_000;
    const r5 = limiter.check("ip-1", policy);
    expect(r5.allowed).toBe(true);
    expect(r5.remaining).toBe(0); // 2 previous still in window + 1 new = 3 total

    // Advance past whole window
    nowTime += 20_000;
    const r6 = limiter.check("ip-1", policy);
    expect(r6.allowed).toBe(true);
    expect(r6.remaining).toBe(2);
  });

  it("isolates rate limits between distinct keys", () => {
    let nowTime = 100_000;
    const limiter = new RateLimiter({ now: () => nowTime });
    const policy = { max: 2, windowMs: 5000 };

    limiter.check("key-A", policy);
    limiter.check("key-A", policy);
    expect(limiter.check("key-A", policy).allowed).toBe(false);

    // Key-B is untouched
    expect(limiter.check("key-B", policy).allowed).toBe(true);
  });

  it("evicts oldest keys when maxKeys capacity is reached (bounded memory)", () => {
    let nowTime = 500_000;
    const limiter = new RateLimiter({ maxKeys: 3, now: () => nowTime });
    const policy = { max: 10, windowMs: 60_000 };

    limiter.check("user-1", policy);
    limiter.check("user-2", policy);
    limiter.check("user-3", policy);
    expect(limiter.size()).toBe(3);

    // Adding user-4 must trigger eviction to stay within capacity
    limiter.check("user-4", policy);
    expect(limiter.size()).toBeLessThanOrEqual(3);

    // user-1 was least recently used, so its entry was evicted
    limiter.reset("user-2");
    expect(limiter.size()).toBe(2);

    limiter.reset();
    expect(limiter.size()).toBe(0);
  });

  it("exports valid standard policies for useMeter", () => {
    expect(RATE_LIMIT_POLICIES.auth).toEqual({ max: 5, windowMs: 60_000 });
    expect(RATE_LIMIT_POLICIES.registration).toEqual({ max: 5, windowMs: 60_000 });
    expect(RATE_LIMIT_POLICIES.manualPoll).toEqual({ max: 1, windowMs: 30_000 });
    expect(RATE_LIMIT_POLICIES.oauthDevicePoll).toEqual({ max: 30, windowMs: 60_000 });
  });
});

// ============================================================================
// 4. Safe Client-IP Resolver
// ============================================================================

describe("Safe Client-IP Resolver", () => {
  const previousEnv = process.env["TRUST_PROXY"];

  it("strictly ignores X-Forwarded-For by default (untrusted proxy)", () => {
    delete process.env["TRUST_PROXY"];

    const req = new Request("http://localhost/api/test", {
      headers: {
        "x-forwarded-for": "203.0.113.195, 70.41.3.18",
        "x-real-ip": "198.51.100.22",
      },
    });

    // Default must NOT trust proxy headers
    expect(resolveClientIp(req)).toBe("127.0.0.1");

    // Even if remote address is provided, headers are ignored
    expect(resolveClientIp(req, { remoteAddress: "10.0.0.5" })).toBe("10.0.0.5");
  });

  it("honors X-Forwarded-For leftmost client IP when trustProxy is true", () => {
    const headers = {
      "x-forwarded-for": "198.51.100.42, 10.0.0.1, 172.16.0.2",
    };

    expect(resolveClientIp(headers, { trustProxy: true })).toBe("198.51.100.42");
  });

  it("strips ports and brackets from IPv4 and IPv6 addresses", () => {
    expect(
      resolveClientIp(
        { "x-forwarded-for": "192.0.2.1:54321, 10.0.0.1" },
        { trustProxy: true }
      )
    ).toBe("192.0.2.1");

    expect(
      resolveClientIp(
        { "x-forwarded-for": "[2001:db8::1]:8443, 10.0.0.1" },
        { trustProxy: true }
      )
    ).toBe("2001:db8::1");
  });

  it("skips invalid/spoofed IP fragments in X-Forwarded-For", () => {
    expect(
      resolveClientIp(
        { "x-forwarded-for": "unknown, evil-host, 198.51.100.99" },
        { trustProxy: true }
      )
    ).toBe("198.51.100.99");
  });

  it("falls back to X-Real-IP when X-Forwarded-For is absent and proxy is trusted", () => {
    expect(
      resolveClientIp(
        { "x-real-ip": "203.0.113.88" },
        { trustProxy: true }
      )
    ).toBe("203.0.113.88");
  });

  it("honors process.env.TRUST_PROXY='true'", () => {
    process.env["TRUST_PROXY"] = "true";

    expect(
      resolveClientIp({
        "x-forwarded-for": "203.0.113.77",
      })
    ).toBe("203.0.113.77");

    // Clean up
    if (previousEnv !== undefined) {
      process.env["TRUST_PROXY"] = previousEnv;
    } else {
      delete process.env["TRUST_PROXY"];
    }
  });
});

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import type { Hono } from "hono";
import type { User } from "../src/types";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry, type ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { AuthService } from "../src/core/auth/auth";
import { createServer } from "../src/server/app";
import { RateLimiter, RATE_LIMIT_POLICIES } from "../src/server/security";

// ============================================================================
// Test Environment Setup & Context Helpers
type TestServerApp = Hono<{ Variables: { user: User; sessionToken: string } }>;


interface TestContext {
  vault: StorageVault;
  registry: ProviderRegistry;
  poller: PollerEngine;
  auth: AuthService;
  app: TestServerApp;
  close: () => void;
}

function createTestContext(rateLimiter?: RateLimiter): TestContext {
  const vault = new StorageVault(":memory:");
  const registry = createDefaultRegistry();
  const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
  const auth = new AuthService(vault);
  const app = createServer(vault, poller, registry, auth, rateLimiter ? { rateLimiter } : undefined);

  return {
    vault,
    registry,
    poller,
    auth,
    app,
    close: () => {
      vault.close();
    },
  };
}

async function registerTestUser(
  app: TestServerApp,
  email = "security-test@example.com",
  password = "Password12345678!",
  ip?: string
) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (ip) {
    headers["X-Forwarded-For"] = ip;
  }

  const res = await app.request("/api/auth/register", {
    method: "POST",
    headers,
    body: JSON.stringify({ email, password }),
  });

  const cookieHeader = res.headers.get("Set-Cookie");
  const cookie = cookieHeader ? cookieHeader.split(";")[0]! : "";
  const body = (await res.json().catch(() => ({}))) as { user?: { id: string; email: string } };
  return { res, cookie, status: res.status, user: body.user };
}

describe("Security HTTP Tests", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Isolate environment variables before each test
    delete process.env["CORS_ALLOWED_ORIGINS"];
    delete process.env["USEMETER_ALLOWED_ORIGINS"];
    delete process.env["TRUST_PROXY"];
    process.env["NODE_ENV"] = "test";
  });

  afterEach(() => {
    // Restore original environment variables
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  // ==========================================================================
  // 1. Security Response Headers
  // ==========================================================================
  describe("Security Response Headers", () => {
    it("applies standard baseline security headers to public health endpoint", async () => {
      const ctx = createTestContext();
      try {
        const res = await ctx.app.request("/health");
        expect(res.status).toBe(200);

        // Standard security headers
        expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(res.headers.get("X-Frame-Options")).toBe("DENY");
        expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");

        // Content-Security-Policy
        const csp = res.headers.get("Content-Security-Policy");
        expect(csp).toBeTruthy();
        expect(csp).toContain("default-src 'self'");
        expect(csp).toContain("script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com");
        expect(csp).toContain("style-src 'self' 'unsafe-inline'");
        expect(csp).toContain("frame-ancestors 'none'");

        // Permissions-Policy
        const permissions = res.headers.get("Permissions-Policy");
        expect(permissions).toBeTruthy();
        expect(permissions).toContain("camera=()");
        expect(permissions).toContain("microphone=()");
        expect(permissions).toContain("geolocation=()");

        // In non-secure HTTP test mode, HSTS must not be set
        expect(res.headers.get("Strict-Transport-Security")).toBeNull();
      } finally {
        ctx.close();
      }
    });

    it("applies security headers to unauthenticated and auth page responses", async () => {
      const ctx = createTestContext();
      try {
        const loginRes = await ctx.app.request("/login");
        expect(loginRes.status).toBe(200);
        expect(loginRes.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(loginRes.headers.get("X-Frame-Options")).toBe("DENY");
        expect(loginRes.headers.get("Content-Security-Policy")).toContain("default-src 'self'");

        const registerRes = await ctx.app.request("/register");
        expect(registerRes.status).toBe(200);
        expect(registerRes.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(registerRes.headers.get("X-Frame-Options")).toBe("DENY");
        expect(registerRes.headers.get("Content-Security-Policy")).toBeTruthy();
      } finally {
        ctx.close();
      }
    });

    it("applies security headers to protected dashboard and API routes", async () => {
      const ctx = createTestContext();
      try {
        const { cookie } = await registerTestUser(ctx.app);
        expect(cookie).toBeTruthy();

        // Protected dashboard HTML
        const dashRes = await ctx.app.request("/", {
          headers: { Cookie: cookie },
        });
        expect(dashRes.status).toBe(200);
        expect(dashRes.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(dashRes.headers.get("X-Frame-Options")).toBe("DENY");
        expect(dashRes.headers.get("Content-Security-Policy")).toContain("default-src 'self'");

        // Protected JSON API
        const credsRes = await ctx.app.request("/api/credentials", {
          headers: { Cookie: cookie },
        });
        expect(credsRes.status).toBe(200);
        expect(credsRes.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(credsRes.headers.get("X-Frame-Options")).toBe("DENY");
      } finally {
        ctx.close();
      }
    });

    it("includes Strict-Transport-Security (HSTS) when request is HTTPS or in production", async () => {
      const ctx = createTestContext();
      try {
        // 1. Direct HTTPS URL request
        const httpsRes = await ctx.app.request("https://localhost/health");
        expect(httpsRes.status).toBe(200);
        const hstsHeader = httpsRes.headers.get("Strict-Transport-Security");
        expect(hstsHeader).toBeTruthy();
        expect(hstsHeader).toContain("max-age=");
        expect(hstsHeader).toContain("includeSubDomains");

        // 2. Production NODE_ENV
        process.env["NODE_ENV"] = "production";
        const prodRes = await ctx.app.request("http://localhost/health");
        expect(prodRes.status).toBe(200);
        expect(prodRes.headers.get("Strict-Transport-Security")).toContain("includeSubDomains");
      } finally {
        ctx.close();
      }
    });
  });

  // ==========================================================================
  // 2. CORS Behavior & Origin Enforcement
  // ==========================================================================
  describe("CORS Behavior & Origin Enforcement", () => {
    it("enforces default same-origin-only behavior and does not reflect untrusted origins", async () => {
      const ctx = createTestContext();
      try {
        const untrustedOrigin = "https://malicious-site.attacker.com";

        // GET request with untrusted origin
        const res = await ctx.app.request("/health", {
          method: "GET",
          headers: {
            Origin: untrustedOrigin,
          },
        });
        expect(res.status).toBe(200);

        // Must NOT reflect the untrusted origin in Access-Control-Allow-Origin
        const allowOrigin = res.headers.get("Access-Control-Allow-Origin");
        expect(allowOrigin === null || allowOrigin !== untrustedOrigin).toBe(true);

        // Preflight OPTIONS request with untrusted origin
        const preflight = await ctx.app.request("/api/credentials", {
          method: "OPTIONS",
          headers: {
            Origin: untrustedOrigin,
            "Access-Control-Request-Method": "POST",
          },
        });
        const preflightAllowOrigin = preflight.headers.get("Access-Control-Allow-Origin");
        expect(preflightAllowOrigin === null || preflightAllowOrigin !== untrustedOrigin).toBe(true);
      } finally {
        ctx.close();
      }
    });

    it("never reflects credentials (Access-Control-Allow-Credentials) for unknown cross-origin requests", async () => {
      const ctx = createTestContext();
      try {
        const unknownOrigin = "http://phishing.example.org";
        const res = await ctx.app.request("/api/auth/login", {
          method: "POST",
          headers: {
            Origin: unknownOrigin,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email: "victim@example.com", password: "wrong" }),
        });

        // The unknown origin must not receive credential reflection
        const allowOrigin = res.headers.get("Access-Control-Allow-Origin");
        const allowCredentials = res.headers.get("Access-Control-Allow-Credentials");

        if (allowOrigin === unknownOrigin) {
          // If origin were reflected (which is a bug), credentials must definitely not be true
          expect(allowCredentials).not.toBe("true");
        } else {
          // Properly not allowed
          expect(allowOrigin === null || allowOrigin === "").toBe(true);
        }
      } finally {
        ctx.close();
      }
    });

    it("permits explicitly allowlisted origins configured via CORS_ALLOWED_ORIGINS", async () => {
      process.env["CORS_ALLOWED_ORIGINS"] = "https://trusted-dashboard.internal, https://partner.app.com";
      const ctx = createTestContext();
      try {
        // 1. Allowed origin request
        const allowedRes = await ctx.app.request("/health", {
          method: "GET",
          headers: {
            Origin: "https://trusted-dashboard.internal",
          },
        });
        expect(allowedRes.status).toBe(200);
        expect(allowedRes.headers.get("Access-Control-Allow-Origin")).toBe("https://trusted-dashboard.internal");
        expect(allowedRes.headers.get("Access-Control-Allow-Credentials")).toBe("true");

        // 2. Second allowed origin from list
        const partnerRes = await ctx.app.request("/health", {
          method: "GET",
          headers: {
            Origin: "https://partner.app.com",
          },
        });
        expect(partnerRes.status).toBe(200);
        expect(partnerRes.headers.get("Access-Control-Allow-Origin")).toBe("https://partner.app.com");

        // 3. Subdomain or non-allowlisted origin is rejected
        const attackerRes = await ctx.app.request("/health", {
          method: "GET",
          headers: {
            Origin: "https://evil.partner.app.com",
          },
        });
        const attackerAllowOrigin = attackerRes.headers.get("Access-Control-Allow-Origin");
        expect(attackerAllowOrigin === null || attackerAllowOrigin !== "https://evil.partner.app.com").toBe(true);
      } finally {
        ctx.close();
      }
    });

    it("accepts same-origin forwarded HTTPS requests when TRUST_PROXY is enabled", async () => {
      process.env["TRUST_PROXY"] = "true";
      const ctx = createTestContext();
      try {
        const { cookie } = await registerTestUser(ctx.app, "proxy-admin@example.com");
        const res = await ctx.app.request("/api/admin/invitations", {
          method: "POST",
          headers: {
            Cookie: cookie,
            Origin: "https://usemeter.example.com",
            Host: "127.0.0.1:3100",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "usemeter.example.com",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email: "invitee@example.com" }),
        });
        expect(res.status).not.toBe(403);
        const body = (await res.json()) as { error?: string };
        expect(body.error).not.toBe("Cross-origin request rejected");
      } finally {
        ctx.close();
      }
    });

    it("does not trust forwarded origin headers when TRUST_PROXY is disabled", async () => {
      delete process.env["TRUST_PROXY"];
      const ctx = createTestContext();
      try {
        const { cookie } = await registerTestUser(ctx.app, "untrusted-proxy@example.com");
        const res = await ctx.app.request("/api/admin/invitations", {
          method: "POST",
          headers: {
            Cookie: cookie,
            Origin: "https://usemeter.example.com",
            Host: "127.0.0.1:3100",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "usemeter.example.com",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email: "invitee@example.com" }),
        });
        expect(res.status).toBe(403);
        expect((await res.json()).error).toBe("Cross-origin request rejected");
      } finally {
        ctx.close();
      }
    });


    it("rejects wildcard origin with credentials when allowlist is set to *", async () => {
      process.env["CORS_ALLOWED_ORIGINS"] = "*";
      const ctx = createTestContext();
      try {
        const res = await ctx.app.request("/health", {
          method: "GET",
          headers: {
            Origin: "https://arbitrary-attacker.com",
          },
        });
        // RFC 6454 and CORS specification: '*' is strictly forbidden when credentials are true
        const allowOrigin = res.headers.get("Access-Control-Allow-Origin");
        const allowCreds = res.headers.get("Access-Control-Allow-Credentials");
        if (allowCreds === "true") {
          expect(allowOrigin).not.toBe("*");
          expect(allowOrigin).not.toBe("https://arbitrary-attacker.com");
        }
      } finally {
        ctx.close();
      }
    });
  });

  // ==========================================================================
  // 3. Authentication Rate Limiting
  // ==========================================================================
  describe("Authentication Rate Limiting", () => {
    it("enforces RATE_LIMIT_POLICIES.auth on POST /api/auth/login and responds with 429 and Retry-After", async () => {
      process.env["TRUST_PROXY"] = "true";
      const ctx = createTestContext();
      try {
        const clientIp = "198.51.100.42";
        const maxAttempts = RATE_LIMIT_POLICIES.auth.max; // 5

        // First 5 attempts: fail with authentication error (e.g. 400 or 401)
        for (let i = 1; i <= maxAttempts; i++) {
          const res = await ctx.app.request("/api/auth/login", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Forwarded-For": clientIp,
            },
            body: JSON.stringify({ email: "victim@example.com", password: `WrongPassword${i}!` }),
          });
          expect(res.status).not.toBe(429);
        }

        // 6th attempt: must trigger rate limit 429
        const blockedRes = await ctx.app.request("/api/auth/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": clientIp,
          },
          body: JSON.stringify({ email: "victim@example.com", password: "Password12345678!" }),
        });

        expect(blockedRes.status).toBe(429);

        // Verify Retry-After header
        const retryAfter = blockedRes.headers.get("Retry-After");
        expect(retryAfter).toBeTruthy();
        expect(Number(retryAfter)).toBeGreaterThan(0);

        // Verify safe response body structure without leaking internal state
        const json = (await blockedRes.json()) as { success: boolean; error: string; retryAfter?: number };
        expect(json.success).toBe(false);
        expect(json.error).toMatch(/too many/i);
        expect(json.retryAfter).toBeDefined();

        // A different IP is NOT blocked
        const otherIpRes = await ctx.app.request("/api/auth/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": "198.51.100.99",
          },
          body: JSON.stringify({ email: "victim@example.com", password: "WrongPassword!" }),
        });
        expect(otherIpRes.status).not.toBe(429);
      } finally {
        ctx.close();
      }
    });

    it("enforces RATE_LIMIT_POLICIES.registration on POST /api/auth/register and responds with 429 and Retry-After", async () => {
      process.env["TRUST_PROXY"] = "true";
      const ctx = createTestContext();
      try {
        const clientIp = "203.0.113.88";
        const maxAttempts = RATE_LIMIT_POLICIES.registration.max; // 5

        // First 5 attempts
        for (let i = 1; i <= maxAttempts; i++) {
          const res = await ctx.app.request("/api/auth/register", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Forwarded-For": clientIp,
            },
            body: JSON.stringify({ email: `user${i}@example.com`, password: "Password12345678!" }),
          });
          expect(res.status).not.toBe(429);
        }

        // 6th attempt: must trigger rate limit 429
        const blockedRes = await ctx.app.request("/api/auth/register", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": clientIp,
          },
          body: JSON.stringify({ email: "another-user@example.com", password: "Password12345678!" }),
        });

        expect(blockedRes.status).toBe(429);
        const retryAfter = blockedRes.headers.get("Retry-After");
        expect(retryAfter).toBeTruthy();
        expect(Number(retryAfter)).toBeGreaterThan(0);
      } finally {
        ctx.close();
      }
    });
    it("rate-limits invitation acceptance with the shared registration window and trusted client IP", async () => {
      process.env["TRUST_PROXY"] = "true";
      let now = 1_000_000;
      const ctx = createTestContext(new RateLimiter({ now: () => now }));
      try {
        const token = "0000000000000000000000000000000000000000000000000000000000000000";
        const accept = (ip: string) =>
          ctx.app.request(`/api/invitations/${token}/accept`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
            body: JSON.stringify({ password: "Valid-Strong-Password-123!" }),
          });
        const clientIp = "203.0.113.88";

        for (let i = 0; i < RATE_LIMIT_POLICIES.registration.max; i += 1) {
          expect((await accept(clientIp)).status).toBe(400);
        }
        const blocked = await accept(clientIp);
        expect(blocked.status).toBe(429);
        expect(Number(blocked.headers.get("Retry-After"))).toBeGreaterThan(0);

        now += RATE_LIMIT_POLICIES.registration.windowMs + 1;
        expect((await accept(clientIp)).status).toBe(400);

        for (let i = 1; i < RATE_LIMIT_POLICIES.registration.max; i += 1) {
          await ctx.app.request("/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Forwarded-For": clientIp },
            body: JSON.stringify({}),
          });
        }
        expect((await accept(clientIp)).status).toBe(429);
        expect((await accept("198.51.100.42")).status).toBe(400);
      } finally {
        ctx.close();
      }
    });

    it("does not rate-limit static authentication pages or health checks", async () => {
      process.env["TRUST_PROXY"] = "true";
      const ctx = createTestContext();
      try {
        const ip = "192.0.2.100";
        // Perform 10 rapid GET requests to /login and /health
        for (let i = 0; i < 10; i++) {
          const loginRes = await ctx.app.request("/login", {
            headers: { "X-Forwarded-For": ip },
          });
          expect(loginRes.status).toBe(200);

          const healthRes = await ctx.app.request("/health", {
            headers: { "X-Forwarded-For": ip },
          });
          expect(healthRes.status).toBe(200);
        }
      } finally {
        ctx.close();
      }
    });
  });

  // ==========================================================================
  // 4. Poll Rate Limiting (Keyed by User + Credential)
  // ==========================================================================
  describe("Poll Rate Limiting (User + Credential Keyed)", () => {
    it("rate-limits single-credential poll (POST /api/credentials/:id/poll) by user and credential ID", async () => {
      const ctx = createTestContext();
      try {
        // Register two distinct users
        const { cookie: cookieUser1 } = await registerTestUser(ctx.app, "user1@example.com", "Password12345678!");
        const { cookie: cookieUser2 } = await registerTestUser(ctx.app, "user2@example.com", "Password12345678!");

        const fakeCredA = "fake-cred-aaaa-1111";
        const fakeCredB = "fake-cred-bbbb-2222";

        // User 1 requests fakeCredA -> 1st call executes (returns 404 or 400 since cred doesn't exist, but consumes rate limit)
        const firstCall = await ctx.app.request(`/api/credentials/${fakeCredA}/poll`, {
          method: "POST",
          headers: { Cookie: cookieUser1 },
        });
        expect(firstCall.status).not.toBe(429);

        // User 1 requests fakeCredA immediately again -> 2nd call hits rate limit 429
        const secondCall = await ctx.app.request(`/api/credentials/${fakeCredA}/poll`, {
          method: "POST",
          headers: { Cookie: cookieUser1 },
        });
        expect(secondCall.status).toBe(429);

        const retryAfter = secondCall.headers.get("Retry-After");
        expect(retryAfter).toBeTruthy();
        expect(Number(retryAfter)).toBeGreaterThan(0);

        // Verification of keying:
        // 1. Same User 1 on a DIFFERENT credential (fakeCredB) is NOT blocked
        const differentCredRes = await ctx.app.request(`/api/credentials/${fakeCredB}/poll`, {
          method: "POST",
          headers: { Cookie: cookieUser1 },
        });
        expect(differentCredRes.status).not.toBe(429);

        // 2. DIFFERENT User 2 on the SAME credential (fakeCredA) is NOT blocked
        const differentUserRes = await ctx.app.request(`/api/credentials/${fakeCredA}/poll`, {
          method: "POST",
          headers: { Cookie: cookieUser2 },
        });
        expect(differentUserRes.status).not.toBe(429);
      } finally {
        ctx.close();
      }
    });

    it("rate-limits whole-account poll (POST /api/poll) by user without making upstream calls", async () => {
      const ctx = createTestContext();
      try {
        const { cookie } = await registerTestUser(ctx.app, "poller-user@example.com", "Password12345678!");

        // 1st call succeeds (no credentials saved, returns 200 with count: 0)
        const firstPoll = await ctx.app.request("/api/poll", {
          method: "POST",
          headers: { Cookie: cookie },
        });
        expect(firstPoll.status).toBe(200);

        // Immediate 2nd call hits manualPoll rate limit (1 per 30s)
        const secondPoll = await ctx.app.request("/api/poll", {
          method: "POST",
          headers: { Cookie: cookie },
        });
        expect(secondPoll.status).toBe(429);
        expect(secondPoll.headers.get("Retry-After")).toBeTruthy();
      } finally {
        ctx.close();
      }
    });
  });

  // ==========================================================================
  // 5. OAuth & Status Abuse Rate Limiting
  // ==========================================================================
  describe("OAuth & Status Abuse Rate Limiting", () => {
    it("enforces RATE_LIMIT_POLICIES.oauthDevicePoll on OAuth device poll routes without leaking token data", async () => {
      process.env["TRUST_PROXY"] = "true";
      const originalFetch = globalThis.fetch;
      let providerCalls = 0;
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url === "https://auth.openai.com/api/accounts/deviceauth/usercode") {
          providerCalls++;
          return Response.json({ device_auth_id: "test-device-auth-uuid-9999", user_code: "WDJB-TEST" });
        }
        throw new Error(`Unexpected synthetic device OAuth URL: ${url}`);
      }) as typeof fetch;
      const rateLimiter = new RateLimiter();
      const ctx = createTestContext(rateLimiter);
      let ownerCookie = "";
      let sessionId = "";
      try {
        const { cookie, user } = await registerTestUser(ctx.app, "oauth-tester@example.com", "Password12345678!", "198.51.100.10");
        ownerCookie = cookie;
        expect(user?.id).toBeTruthy();
        const clientIp = "198.51.100.77";
        const maxPolls = RATE_LIMIT_POLICIES.oauthDevicePoll.max;
        const initiation = await ctx.app.request("/api/oauth/codex/initiate", {
          method: "POST",
          headers: { Cookie: cookie },
        });
        expect(initiation.status).toBe(200);
        const initiateBody = await initiation.json() as {
          data: { deviceAuthId: string; userCode: string; sessionId: string };
        };
        const { deviceAuthId, userCode } = initiateBody.data;
        sessionId = initiateBody.data.sessionId;

        for (let i = 1; i <= maxPolls; i++) {
          rateLimiter.check(`oauthDevicePoll:${user!.id}:codex:${deviceAuthId}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
        }

        const blockedRes = await ctx.app.request("/api/oauth/codex/poll", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": clientIp,
            Cookie: cookie,
          },
          body: JSON.stringify({ deviceAuthId, userCode }),
        });

        expect(blockedRes.status).toBe(429);
        const retryAfter = blockedRes.headers.get("Retry-After");
        expect(retryAfter).toBeTruthy();
        expect(Number(retryAfter)).toBeGreaterThan(0);
        const text = await blockedRes.text();
        expect(text).not.toContain("secret");
        expect(text).not.toContain("access_token");
        expect(text).not.toContain("refreshToken");
        expect(text).not.toContain("code_verifier");
        expect(text).not.toContain("authorizationCode");

        const json = JSON.parse(text) as { status?: string; success?: boolean; error: string };
        expect(json.status === "error" || json.success === false).toBe(true);
        expect(json.error).toMatch(/too many/i);
        expect(providerCalls).toBe(1);
      } finally {
        if (sessionId && ownerCookie) {
          await ctx.app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
            method: "DELETE",
            headers: { Cookie: ownerCookie },
          });
        }
        globalThis.fetch = originalFetch;
        ctx.close();
      }
    });

    it("enforces OAuth status polling rate limits on session status endpoint", async () => {
      process.env["TRUST_PROXY"] = "true";
      const ctx = createTestContext();
      try {
        const { cookie } = await registerTestUser(ctx.app, "oauth-status-tester@example.com", "Password12345678!", "198.51.100.20");
        const clientIp = "198.51.100.88";
        const sessionId = "browser-oauth-session-5555";
        const maxPolls = RATE_LIMIT_POLICIES.oauthDevicePoll.max; // 30

        for (let i = 1; i <= maxPolls; i++) {
          const res = await ctx.app.request(`/api/oauth/status/${sessionId}`, {
            method: "GET",
            headers: {
              "X-Forwarded-For": clientIp,
              Cookie: cookie,
            },
          });
          expect(res.status).not.toBe(429);
        }

        // 31st call: blocked
        const blockedRes = await ctx.app.request(`/api/oauth/status/${sessionId}`, {
          method: "GET",
          headers: {
            "X-Forwarded-For": clientIp,
            Cookie: cookie,
          },
        });
        expect(blockedRes.status).toBe(429);
        expect(blockedRes.headers.get("Retry-After")).toBeTruthy();
        const json = (await blockedRes.json()) as { status: string; error: string; retryAfter?: number };
        expect(json.status).toBe("error");
        expect(json.error).toMatch(/too many/i);
      } finally {
        ctx.close();
      }
    });
  });
});

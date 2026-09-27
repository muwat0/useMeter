import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { PollerEngine } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import type { UsageReport } from "../src/types";
import { createServer, type AppInstance } from "../src/server/app";
import { getDevinRedirectUri, isDevinHostedFlow, initiateDevinAuth } from "../src/core/oauth/devin";

const mockSuccessDevinAdapter: ProviderAdapter = {
  id: "devin",
  supports(provider: string) {
    return provider === "devin";
  },
  async fetchUsage(): Promise<UsageReport> {
    return {
      provider: "devin",
      accountLabel: "devin-engineer@example.com",
      limits: [{ id: "sessions", label: "Sessions", amount: { used: 1, limit: 10, unit: "requests" }, status: "ok" }],
      fetchedAt: Date.now(),
    };
  },
};

const mockFailDevinAdapter: ProviderAdapter = {
  id: "devin",
  supports(provider: string) {
    return provider === "devin";
  },
  async fetchUsage(): Promise<UsageReport> {
    return {
      provider: "devin",
      error: "Devin quota check failed: account suspended",
      limits: [],
      fetchedAt: Date.now(),
    };
  },
};

function context(customAdapter: ProviderAdapter = mockSuccessDevinAdapter) {
  const vault = new StorageVault(":memory:");
  const registry = new ProviderRegistry();
  registry.register(customAdapter);
  const poller = new PollerEngine(vault, registry);
  const app = createServer(vault, poller, registry);
  return { vault, app, poller, registry };
}

async function register(app: AppInstance, email: string = "devin-test@example.com") {
  const response = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "Password12345678!" }),
  });
  return response.headers.get("Set-Cookie")!.split(";")[0]!;
}

describe("Devin OAuth core functions", () => {
  it("generates unpredictable CSPRNG UUID states that are unique per initiation", () => {
    const res1 = initiateDevinAuth();
    const res2 = initiateDevinAuth();

    // Verify UUID format (8-4-4-4-12 hex chars)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    expect(res1.state).toMatch(uuidRegex);
    expect(res2.state).toMatch(uuidRegex);

    // Verify uniqueness across invocations
    expect(res1.state).not.toBe(res2.state);
    expect(res1.verifier).not.toBe(res2.verifier);
  });

  it("uses DEVIN_OAUTH_REDIRECT_URI when configured with valid HTTPS and exact path", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";
      expect(getDevinRedirectUri()).toBe("https://usemeter.example.com/api/oauth/devin/callback");
      expect(isDevinHostedFlow()).toBe(true);
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects non-HTTPS hosted DEVIN_OAUTH_REDIRECT_URI", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "http://usemeter.example.com/api/oauth/devin/callback";
      expect(() => getDevinRedirectUri()).toThrow("must use HTTPS");
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects hosted DEVIN_OAUTH_REDIRECT_URI with incorrect pathname", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/callback";
      expect(() => getDevinRedirectUri()).toThrow("must be exactly '/api/oauth/devin/callback'");
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects DEVIN_OAUTH_REDIRECT_URI containing userinfo", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://user:pass@usemeter.example.com/api/oauth/devin/callback";
      expect(() => getDevinRedirectUri()).toThrow("must not contain userinfo");
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects DEVIN_OAUTH_REDIRECT_URI containing a hash fragment", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback#section";
      expect(() => getDevinRedirectUri()).toThrow("must not contain a hash or fragment");
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects DEVIN_OAUTH_REDIRECT_URI with unsupported protocol", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "ftp://127.0.0.1:59653/callback";
      expect(() => getDevinRedirectUri()).toThrow("must use HTTPS, or HTTP for a local loopback address");
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("accepts only the exact local listener URI for loopback redirects", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "http://127.0.0.1:59653/callback";
      expect(getDevinRedirectUri()).toBe("http://127.0.0.1:59653/callback");
      expect(isDevinHostedFlow()).toBe(false);

      const rejectedUris = [
        "http://localhost:59653/callback",
        "http://[::1]:59653/callback",
        "http://127.0.0.1:59654/callback",
        "http://127.0.0.1:59653/other",
        "https://127.0.0.1:59653/callback",
      ];
      for (const uri of rejectedUris) {
        process.env["DEVIN_OAUTH_REDIRECT_URI"] = uri;
        let message = "";
        try {
          getDevinRedirectUri();
        } catch (error) {
          message = error instanceof Error ? error.message : "";
        }
        expect(message).toContain("must exactly match the local callback listener");
        expect(message).not.toContain(uri);
      }
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects query strings and omits configured URI values from validation errors", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const secret = "should-not-leak";
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = `https://usemeter.example.com/api/oauth/devin/callback?token=${secret}`;
      let message = "";
      try {
        getDevinRedirectUri();
      } catch (error) {
        message = error instanceof Error ? error.message : "";
      }
      expect(message).toContain("must not contain a query string");
      expect(message).not.toContain(secret);
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
    }
  });

  it("rejects an explicitly configured loopback redirect in production", () => {
    const originalEnv = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const originalNodeEnv = process.env["NODE_ENV"];
    const originalAllowLocal = process.env["DEVIN_ALLOW_LOCAL_LOOPBACK"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "http://127.0.0.1:59653/callback";
      process.env["NODE_ENV"] = "production";
      process.env["DEVIN_ALLOW_LOCAL_LOOPBACK"] = "true";
      expect(() => getDevinRedirectUri()).toThrow("loopback redirect URIs are not allowed in production");
    } finally {
      if (originalEnv !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = originalEnv;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      if (originalNodeEnv !== undefined) process.env["NODE_ENV"] = originalNodeEnv;
      else delete process.env["NODE_ENV"];
      if (originalAllowLocal !== undefined) process.env["DEVIN_ALLOW_LOCAL_LOOPBACK"] = originalAllowLocal;
      else delete process.env["DEVIN_ALLOW_LOCAL_LOOPBACK"];
    }
  });

  it("throws clear error in production when DEVIN_OAUTH_REDIRECT_URI is missing", () => {
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const origNodeEnv = process.env["NODE_ENV"];
    try {
      delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      process.env["NODE_ENV"] = "production";
      expect(() => getDevinRedirectUri()).toThrow("DEVIN_OAUTH_REDIRECT_URI is not configured");
    } finally {
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      if (origNodeEnv !== undefined) process.env["NODE_ENV"] = origNodeEnv;
      else delete process.env["NODE_ENV"];
    }
  });
});

describe("Devin public OAuth callback & initiate routes", () => {
  it("is reachable without an application session and rejects unknown or missing state", async () => {
    const { vault, app } = context();
    try {
      const resNoState = await app.request("/api/oauth/devin/callback?code=some-code");
      expect(resNoState.status).toBe(400);

      const resUnknownState = await app.request("/api/oauth/devin/callback?state=unknown&code=some-code");
      expect(resUnknownState.status).toBe(400);
      expect(await resUnknownState.text()).toContain("Invalid or expired authorization session");
    } finally {
      vault.close();
    }
  });

  it("fails initiation clearly in production when DEVIN_OAUTH_REDIRECT_URI is not set", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const origNodeEnv = process.env["NODE_ENV"];
    try {
      delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      process.env["NODE_ENV"] = "production";

      const cookie = await register(app);
      const res = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(400);
      const json = (await res.json()) as { success: boolean; error: string };
      expect(json.success).toBe(false);
      expect(json.error).toContain("DEVIN_OAUTH_REDIRECT_URI is not configured");
    } finally {
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      if (origNodeEnv !== undefined) process.env["NODE_ENV"] = origNodeEnv;
      else delete process.env["NODE_ENV"];
      vault.close();
    }
  });

  it("initiates hosted flow with configured redirect URI", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookie = await register(app);
      const res = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { success: boolean; data: { authUrl: string; sessionId: string; redirectUri: string } };
      expect(json.success).toBe(true);
      expect(json.data.redirectUri).toBe("https://usemeter.example.com/api/oauth/devin/callback");
      expect(json.data.authUrl).toContain(encodeURIComponent("https://usemeter.example.com/api/oauth/devin/callback"));
    } finally {
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });

  it("handles user denial gracefully", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookie = await register(app);
      const initRes = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      const { sessionId } = ((await initRes.json()) as { data: { sessionId: string } }).data;

      const callbackRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&error=access_denied`);
      expect(callbackRes.status).toBe(200);
      const html = await callbackRes.text();
      expect(html).toContain("Devin Login Failed");
      expect(html).toContain("Authorization was denied");

      const statusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookie },
      });
      const statusJson = (await statusRes.json()) as { status: string; error?: string };
      expect(statusJson.status).toBe("error");
      expect(statusJson.error).toBe("Authorization was denied");
    } finally {
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });

  it("safely handles arbitrary OAuth error without reflecting raw error in HTML", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookie = await register(app);
      const initRes = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      type InitiatePayload = { data: { sessionId: string } };
      const initJson = (await initRes.json()) as InitiatePayload;
      const sessionId = initJson.data.sessionId;

      const callbackRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&error=<script>alert("xss")</script>`);
      expect(callbackRes.status).toBe(200);
      const html = await callbackRes.text();
      expect(html).toContain("Devin Login Failed");
      expect(html).toContain("Authorization failed. You can close this tab.");
      expect(html).not.toContain("alert(\"xss\")");

      const statusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookie },
      });
      const statusJson = (await statusRes.json()) as { status: string; error?: string };
      expect(statusJson.status).toBe("error");
      expect(statusJson.error).toBe('<script>alert("xss")</script>');
    } finally {
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });

  it("completes code exchange, isolates tenants, and prevents replay", async () => {
    const { vault, app } = context(mockSuccessDevinAdapter);
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const originalFetch = globalThis.fetch;

    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookieUser1 = await register(app, "user1@example.com");
      const cookieUser2 = await register(app, "user2@example.com");

      const initRes = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookieUser1 },
      });
      const { sessionId } = ((await initRes.json()) as { data: { sessionId: string } }).data;

      // Mock Devin token endpoint strictly: never call out to real network
      const fakeJwt = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ email: "devin-engineer@example.com" })).toString("base64url")}.fakesig`;
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/auth/cli/token")) {
          return new Response(JSON.stringify({ token: fakeJwt }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`Unexpected external network call intercepted: ${url}`);
      }) as typeof fetch;

      // First callback attempt: success
      const callbackRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&code=auth-code-123`);
      expect(callbackRes.status).toBe(200);
      const html = await callbackRes.text();
      expect(html).toContain("Devin Login Successful");

      // Verify status polling by User 1 (initiator)
      const statusRes1 = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookieUser1 },
      });
      expect(statusRes1.status).toBe(200);
      const statusJson1 = (await statusRes1.json()) as { status: string; accountLabel?: string; provider: string };
      expect(statusJson1.status).toBe("complete");
      expect(statusJson1.accountLabel).toBe("devin-engineer@example.com");
      expect(statusJson1.provider).toBe("devin");

      // Tenant isolation: User 2 attempting to poll User 1's session gets 404
      const statusRes2 = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookieUser2 },
      });
      expect(statusRes2.status).toBe(404);


      // Assert credential persists in vault and is returned for User 1
      const credsRes1 = await app.request("/api/credentials", {
        headers: { Cookie: cookieUser1 },
      });
      expect(credsRes1.status).toBe(200);
      type CredentialsResponse = { success: boolean; data: Array<{ provider: string; accountLabel: string }> };
      const credsPayload1 = (await credsRes1.json()) as CredentialsResponse;
      expect(credsPayload1.data.some(c => c.provider === "devin" && c.accountLabel === "devin-engineer@example.com")).toBe(true);

      // Assert User 2 has no Devin credentials (tenant persistence isolation)
      const credsRes2 = await app.request("/api/credentials", {
        headers: { Cookie: cookieUser2 },
      });
      expect(credsRes2.status).toBe(200);
      const credsPayload2 = (await credsRes2.json()) as CredentialsResponse;
      expect(credsPayload2.data.some(c => c.provider === "devin")).toBe(false);
      // Replay attempt: second callback with same state is rejected with "already used"
      const replayRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&code=auth-code-123`);
      expect(replayRes.status).toBe(400);
      expect(await replayRes.text()).toContain("already used");
    } finally {
      globalThis.fetch = originalFetch;
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });

  it("handles token exchange failure cleanly", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const originalFetch = globalThis.fetch;

    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookie = await register(app);
      const initRes = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      const { sessionId } = ((await initRes.json()) as { data: { sessionId: string } }).data;

      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/auth/cli/token")) {
          return new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`Unexpected external network call intercepted: ${url}`);
      }) as typeof fetch;

      const callbackRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&code=bad-code`);
      expect(callbackRes.status).toBe(200);
      const html = await callbackRes.text();
      expect(html).toContain("Devin Login Failed");

      const statusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookie },
      });
      const statusJson = (await statusRes.json()) as { status: string; error?: string };
      expect(statusJson.status).toBe("error");
      expect(statusJson.error).toContain("failed");
    } finally {
      globalThis.fetch = originalFetch;
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });

  it("uses static generic HTML and sets error in status JSON on initial validation failure", async () => {
    const { vault, app } = context(mockFailDevinAdapter);
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const originalFetch = globalThis.fetch;

    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookie = await register(app);
      const initRes = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      const { sessionId } = ((await initRes.json()) as { data: { sessionId: string } }).data;

      const fakeJwt = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ email: "devin-engineer@example.com" })).toString("base64url")}.fakesig`;
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/auth/cli/token")) {
          return new Response(JSON.stringify({ token: fakeJwt }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`Unexpected external network call intercepted: ${url}`);
      }) as typeof fetch;

      const callbackRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&code=valid-code`);
      expect(callbackRes.status).toBe(200);
      const html = await callbackRes.text();

      // Verify static generic HTML message: NO raw error unescaped in HTML
      expect(html).toContain("Provider validation failed. Please check your dashboard");
      expect(html).not.toContain("Devin quota check failed");

      // Verify precise error is in authenticated status JSON
      const statusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookie },
      });
      const statusJson = (await statusRes.json()) as { status: string; error?: string };
      expect(statusJson.status).toBe("error");
      expect(statusJson.error).toBe("Devin quota check failed: account suspended");
    } finally {
      globalThis.fetch = originalFetch;
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });

  it("transitions expired Devin pending session to error on status poll without callback, while preserving 404 tenant isolation", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["DEVIN_OAUTH_REDIRECT_URI"];
    const originalNow = Date.now;

    try {
      process.env["DEVIN_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/devin/callback";

      const cookieUser1 = await register(app, "devin-user1@example.com");
      const cookieUser2 = await register(app, "devin-user2@example.com");

      const initRes = await app.request("/api/oauth/devin/initiate", {
        method: "POST",
        headers: { Cookie: cookieUser1 },
      });
      expect(initRes.status).toBe(200);
      const initJson = (await initRes.json()) as { success: boolean; data: { sessionId: string; expiresIn: number } };
      expect(initJson.success).toBe(true);
      expect(initJson.data.expiresIn).toBe(600);
      const { sessionId } = initJson.data;

      // Immediately polled: status is pending
      const initialStatusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookieUser1 },
      });
      expect(initialStatusRes.status).toBe(200);
      const initialStatusJson = (await initialStatusRes.json()) as { status: string };
      expect(initialStatusJson.status).toBe("pending");

      // Advance clock past 10-minute session TTL (600 seconds) deterministically
      const startTime = originalNow();
      Date.now = () => startTime + 10 * 60 * 1000 + 1_000;

      // Other user (User 2) polling User 1's expired session still gets 404 (tenant isolation preserved)
      const foreignStatusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookieUser2 },
      });
      expect(foreignStatusRes.status).toBe(404);
      const foreignJson = (await foreignStatusRes.json()) as { status: string };
      expect(foreignJson.status).toBe("not_found");

      // Initiator (User 1) polling expired session receives terminal error status without needing callback or network
      const expiredStatusRes = await app.request(`/api/oauth/status/${sessionId}`, {
        headers: { Cookie: cookieUser1 },
      });
      expect(expiredStatusRes.status).toBe(200);
      const expiredStatusJson = (await expiredStatusRes.json()) as { status: string; error?: string };
      expect(expiredStatusJson.status).toBe("error");
      expect(expiredStatusJson.error).toBe("Authorization session expired");

      // Any subsequent callback attempt after expiration is rejected cleanly as expired
      const lateCallbackRes = await app.request(`/api/oauth/devin/callback?state=${sessionId}&code=any-code`);
      expect(lateCallbackRes.status).toBe(400);
      expect(await lateCallbackRes.text()).toContain("already used");
    } finally {
      Date.now = originalNow;
      if (origRedirect !== undefined) process.env["DEVIN_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["DEVIN_OAUTH_REDIRECT_URI"];
      vault.close();
    }
  });
});

describe("Google safe config error exposure", () => {
  it("exposes safe actionable configuration remediation on public URI without custom credentials", async () => {
    const { vault, app } = context();
    const origRedirect = process.env["GOOGLE_OAUTH_REDIRECT_URI"];
    const origClientId = process.env["GOOGLE_OAUTH_CLIENT_ID"];
    const origClientSecret = process.env["GOOGLE_OAUTH_CLIENT_SECRET"];

    try {
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";
      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];

      const cookie = await register(app);
      const res = await app.request("/api/oauth/google/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(400);
      const json = (await res.json()) as { success: boolean; error: string };
      expect(json.success).toBe(false);
      expect(json.error).toContain("Public Google OAuth redirect URI requires custom GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET");
    } finally {
      if (origRedirect !== undefined) process.env["GOOGLE_OAUTH_REDIRECT_URI"] = origRedirect;
      else delete process.env["GOOGLE_OAUTH_REDIRECT_URI"];
      if (origClientId !== undefined) process.env["GOOGLE_OAUTH_CLIENT_ID"] = origClientId;
      else delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      if (origClientSecret !== undefined) process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = origClientSecret;
      else delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
      vault.close();
    }
  });
});

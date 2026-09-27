import { describe, expect, it } from "bun:test";
import { GoogleAntigravityAdapter } from "../src/core/providers/google-antigravity";
import { generatePKCE } from "../src/core/oauth/pkce";
import { initiateGoogleAuth } from "../src/core/oauth/google";
import { initiateClaudeAuth } from "../src/core/oauth/claude";
import { initiateGeminiCliAuth } from "../src/core/oauth/gemini-cli";
import { initiateOpenRouterAuth } from "../src/core/oauth/openrouter";
import { initiateZaiAuth } from "../src/core/oauth/zai";
import { initiateDevinAuth } from "../src/core/oauth/devin";
import { initiateCursorAuth } from "../src/core/oauth/cursor";
import { decodeJwtPayload, initiateCodexDeviceAuth } from "../src/core/oauth/codex-device";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";
import type { StoredCredential } from "../src/types";

const mockCred: StoredCredential = {
  id: "google-test-1",
  ownerId: "mock-owner",
  provider: "google-antigravity",
  accountLabel: "Google Test",
  credentialType: "oauth",
  secret: "ya29.mock-google-token",
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

describe("GoogleAntigravityAdapter", () => {
  it("parses quota summary groups with explicit 5h and weekly windows", async () => {
    const adapter = new GoogleAntigravityAdapter();
    expect(adapter.supports("google-antigravity")).toBe(true);
    expect(adapter.supports("gemini")).toBe(true);

    const inOneHour = new Date(Date.now() + 3600 * 1000).toISOString();
    const inTwoDays = new Date(Date.now() + 2 * 24 * 3600 * 1000).toISOString();
    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          groups: [
            {
              displayName: "Gemini Models",
              buckets: [
                { bucketId: "gemini-5h", displayName: "Five Hour Limit Remaining", window: "5h", remainingFraction: 0.85, resetTime: inOneHour },
                { bucketId: "gemini-weekly", displayName: "Weekly Limit Remaining", window: "weekly", remainingFraction: 0.7, resetTime: inTwoDays },
              ],
            },
            {
              displayName: "Claude and GPT models",
              buckets: [
                { bucketId: "3p-5h", displayName: "Five Hour Limit Remaining", window: "5h", remainingFraction: 0.4, resetTime: inOneHour },
                { bucketId: "3p-weekly", displayName: "Weekly Limit Remaining", window: "weekly", remainingFraction: 0.6, resetTime: inTwoDays },
              ],
            },
          ],
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("Antigravity");
    expect(report.limits.length).toBe(4);

    const gemini5h = report.limits.find(l => l.id === "gemini_5h");
    expect(gemini5h?.amount.remaining).toBe(85);
    expect(gemini5h?.amount.used).toBeCloseTo(15, 1);

    const geminiWeekly = report.limits.find(l => l.id === "gemini_weekly");
    expect(geminiWeekly?.amount.remaining).toBe(70);

    const claudeGpt5h = report.limits.find(l => l.id === "claude_gpt_5h");
    expect(claudeGpt5h?.amount.remaining).toBe(40);
    expect(claudeGpt5h?.amount.used).toBeCloseTo(60, 1);

    const claudeGptWeekly = report.limits.find(l => l.id === "claude_gpt_weekly");
    expect(claudeGptWeekly?.amount.remaining).toBe(60);
  });

  it("omits a window instead of rendering a fabricated 100% bar", async () => {
    const adapter = new GoogleAntigravityAdapter();
    const inOneHour = new Date(Date.now() + 3600 * 1000).toISOString();
    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          groups: [
            {
              displayName: "Gemini Models",
              buckets: [
                { bucketId: "gemini-5h", displayName: "Five Hour Limit Remaining", window: "5h", remainingFraction: 0.85, resetTime: inOneHour },
              ],
            },
          ],
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("Antigravity");
    expect(report.limits.map(l => l.id)).toEqual(["gemini_5h"]);
    expect(report.limits.find(l => l.id === "gemini_weekly")).toBeUndefined();
  });

  it("treats an omitted fraction with only resetTime as exhausted", async () => {
    const adapter = new GoogleAntigravityAdapter();
    const inOneHour = new Date(Date.now() + 3600 * 1000).toISOString();
    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          groups: [
            {
              displayName: "Gemini Models",
              buckets: [
                { bucketId: "gemini-5h", displayName: "Five Hour Limit Remaining", window: "5h", resetTime: inOneHour },
              ],
            },
          ],
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    const gemini5h = report.limits.find(l => l.id === "gemini_5h");
    expect(gemini5h?.amount.remaining).toBe(0);
    expect(gemini5h?.amount.used).toBe(100);
    expect(gemini5h?.status).toBe("exhausted");
  });
});

describe("OAuth PKCE & URLs", () => {
  it("generates valid PKCE verifier and challenge", () => {
    const pkce = generatePKCE();
    expect(pkce.verifier).toBeDefined();
    expect(pkce.challenge).toBeDefined();
    expect(pkce.verifier.length).toBeGreaterThan(40);
    expect(pkce.challenge.length).toBeGreaterThan(40);
    expect(pkce.challenge).not.toContain("+");
    expect(pkce.challenge).not.toContain("/");
  });

  it("initiates Google OAuth with cloud-platform scopes", () => {
    const auth = initiateGoogleAuth();
    expect(auth.authUrl).toContain("accounts.google.com");
    expect(auth.authUrl).toContain("code_challenge_method=S256");
    expect(auth.authUrl).toContain("cloud-platform");
    expect(auth.verifier).toBeDefined();
    expect(auth.state).toBeDefined();
  });

  it("initiates Claude OAuth with claude.ai authorize URL", () => {
    const auth = initiateClaudeAuth();
    expect(auth.authUrl).toContain("claude.ai/oauth/authorize");
    expect(auth.authUrl).toContain("code_challenge_method=S256");
    expect(auth.verifier).toBeDefined();
    expect(auth.state).toBeDefined();
  });
  it("initiates Gemini CLI, OpenRouter, ZAI, Devin, and Cursor OAuth flows", async () => {
    const gemini = initiateGeminiCliAuth();
    expect(gemini.authUrl).toContain("accounts.google.com");
    expect(gemini.authUrl).toContain("oauth2callback");

    const openrouter = initiateOpenRouterAuth();
    expect(openrouter.authUrl).toContain("openrouter.ai/auth");
    expect(openrouter.verifier).toBeDefined();

    const zai = initiateZaiAuth();
    expect(zai.authUrl).toContain("chat.z.ai/api/oauth/authorize");
    expect(zai.state).toBeDefined();

    const devin = initiateDevinAuth();
    expect(devin.authUrl).toContain("app.devin.ai/auth/cli/continue");
    expect(devin.verifier).toBeDefined();

    const cursor = await initiateCursorAuth();
    expect(cursor.uuid).toBeDefined();
    expect(cursor.verifier).toBeDefined();
    expect(cursor.expiresIn).toBe(600);
  });

  it("decodes JWT payload correctly", () => {
    // Standard payload: {"sub":"123","email":"test@example.com"}
    const header = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64");
    const payload = Buffer.from(JSON.stringify({ sub: "123", email: "test@example.com" })).toString("base64");
    const fakeJwt = `${header}.${payload}.signature`;

    const decoded = decodeJwtPayload(fakeJwt);
    expect(decoded).not.toBeNull();
    expect(decoded?.["email"]).toBe("test@example.com");
  });
});

describe("Codex Device Auth Initiation", () => {
  it("defaults to 900s (15 min) expiresIn when upstream omits expires_in", async () => {
    const origFetch = globalThis.fetch;
    let fetchCalled = false;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      fetchCalled = true;
      const url = input instanceof Request ? input.url : String(input);
      expect(url).toBe("https://auth.openai.com/api/accounts/deviceauth/usercode");
      expect(init?.method).toBe("POST");
      expect((init?.headers as Record<string, string>)?.["Content-Type"]).toBe("application/json");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body["client_id"]).toBe("app_EMoamEEZ73f0CkXaXp7hrann");

      return new Response(
        JSON.stringify({
          device_auth_id: "test-device-auth-id",
          user_code: "TEST-USER-CODE",
          interval: 5,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as unknown as typeof fetch;

    try {
      const res = await initiateCodexDeviceAuth();
      expect(fetchCalled).toBe(true);
      expect(res.deviceAuthId).toBe("test-device-auth-id");
      expect(res.userCode).toBe("TEST-USER-CODE");
      expect(res.verificationUrl).toBe("https://auth.openai.com/codex/device");
      expect(res.interval).toBe(5);
      expect(res.expiresIn).toBe(900);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("respects upstream expires_in when a shorter lifetime is provided", async () => {
    const origFetch = globalThis.fetch;
    let fetchCalled = false;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      fetchCalled = true;
      const url = input instanceof Request ? input.url : String(input);
      expect(url).toBe("https://auth.openai.com/api/accounts/deviceauth/usercode");
      return new Response(
        JSON.stringify({
          device_auth_id: "test-device-auth-id-2",
          user_code: "TEST-USER-CODE-2",
          interval: 10,
          expires_in: 300,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as unknown as typeof fetch;

    try {
      const res = await initiateCodexDeviceAuth();
      expect(fetchCalled).toBe(true);
      expect(res.deviceAuthId).toBe("test-device-auth-id-2");
      expect(res.userCode).toBe("TEST-USER-CODE-2");
      expect(res.verificationUrl).toBe("https://auth.openai.com/codex/device");
      expect(res.interval).toBe(10);
      expect(res.expiresIn).toBe(300);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
describe("Server OAuth Routes", () => {
  it("handles OAuth initiate endpoints", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Anonymous attempt must be rejected with 401
    const anonRes = await app.request("/api/oauth/google/initiate", { method: "POST" });
    expect(anonRes.status).toBe(401);

    // Register authenticated user
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "oauth-tester@example.com", password: "Password12345678!" }),
    });
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;

    const googleRes = await app.request("/api/oauth/google/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(googleRes.status).toBe(200);
    const googleJson = (await googleRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(googleJson.success).toBe(true);
    expect(googleJson.data.authUrl).toContain("accounts.google.com");

    const claudeRes = await app.request("/api/oauth/claude/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const claudeJson = (await claudeRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(claudeJson.success).toBe(true);
    expect(claudeJson.data.authUrl).toContain("claude.ai");

    const geminiRes = await app.request("/api/oauth/gemini-cli/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const geminiJson = (await geminiRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(geminiJson.success).toBe(true);
    expect(geminiJson.data.authUrl).toContain("accounts.google.com");

    const openrouterRes = await app.request("/api/oauth/openrouter/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const openrouterJson = (await openrouterRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(openrouterJson.success).toBe(true);
    expect(openrouterJson.data.authUrl).toContain("openrouter.ai");

    const zaiRes = await app.request("/api/oauth/zai/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const zaiJson = (await zaiRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(zaiJson.success).toBe(true);
    expect(zaiJson.data.authUrl).toContain("chat.z.ai");

    const devinRes = await app.request("/api/oauth/devin/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const devinJson = (await devinRes.json()) as { success: boolean; data: { authUrl: string; expiresIn?: number } };
    expect(devinJson.success).toBe(true);
    expect(devinJson.data.authUrl).toContain("app.devin.ai");
    expect(devinJson.data.expiresIn).toBe(600);

    const cursorRes = await app.request("/api/oauth/cursor/initiate", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    const cursorJson = (await cursorRes.json()) as { success: boolean; data: { authUrl: string; expiresIn?: number } };
    expect(cursorJson.success).toBe(true);
    expect(cursorJson.data.authUrl).toContain("cursor.com");
    expect(cursorJson.data.expiresIn).toBe(600);

    const origFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          device_auth_id: "test-codex-auth",
          user_code: "CODEX-CODE",
          interval: 5,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as unknown as typeof fetch;

    try {
      const codexRes = await app.request("/api/oauth/codex/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      const codexJson = (await codexRes.json()) as {
        success: boolean;
        data: { deviceAuthId: string; userCode: string; verificationUrl: string; interval: number; expiresIn: number };
      };
      expect(codexRes.status).toBe(200);
      expect(codexJson.success).toBe(true);
      expect(codexJson.data.expiresIn).toBe(900);
      expect(codexJson.data.verificationUrl).toBe("https://auth.openai.com/codex/device");
      expect(codexJson.data.userCode).toBe("CODEX-CODE");
    } finally {
      globalThis.fetch = origFetch;
    }

    vault.close();
  });
});

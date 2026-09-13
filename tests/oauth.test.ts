import { describe, expect, it } from "bun:test";
import { GoogleAntigravityAdapter } from "../src/core/providers/google-antigravity";
import { generatePKCE } from "../src/core/oauth/pkce";
import { initiateGoogleAuth } from "../src/core/oauth/google";
import { initiateClaudeAuth } from "../src/core/oauth/claude";
import { decodeJwtPayload } from "../src/core/oauth/codex-device";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";
import type { StoredCredential } from "../src/types";

const mockCred: StoredCredential = {
  id: "google-test-1",
  provider: "google-antigravity",
  accountLabel: "Google Test",
  credentialType: "oauth",
  secret: "ya29.mock-google-token",
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

describe("GoogleAntigravityAdapter", () => {
  it("parses models and quotaInfo with remainingFraction and resetTime", async () => {
    const adapter = new GoogleAntigravityAdapter();
    expect(adapter.supports("google-antigravity")).toBe(true);
    expect(adapter.supports("gemini")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          models: {
            "gemini-3-flash": {
              displayName: "Gemini 3 Flash",
              quotaInfo: {
                remainingFraction: 0.85,
                resetTime: new Date(Date.now() + 86400 * 1000).toISOString(),
                windowLabel: "Günlük",
              },
            },
            "claude-sonnet-4-6": {
              displayName: "Claude Sonnet 4.6",
              quotaInfo: {
                remainingFraction: 0.4,
                resetTime: new Date(Date.now() + 86400 * 1000).toISOString(),
                windowLabel: "Günlük",
              },
            },
          },
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("google-antigravity");
    expect(report.limits.length).toBe(4);

    const gemini5h = report.limits.find(l => l.id === "gemini_5h");
    expect(gemini5h?.amount.remaining).toBe(85);
    expect(gemini5h?.amount.used).toBeCloseTo(15, 1);

    const geminiWeekly = report.limits.find(l => l.id === "gemini_weekly");
    expect(geminiWeekly?.amount.remaining).toBeDefined();

    const claude5h = report.limits.find(l => l.id === "claude_rolling");
    expect(claude5h?.amount.remaining).toBe(40);
    expect(claude5h?.amount.used).toBeCloseTo(60, 1);

    const claudeWeekly = report.limits.find(l => l.id === "claude_weekly");
    expect(claudeWeekly?.amount.remaining).toBeDefined();
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

describe("Server OAuth Routes", () => {
  it("handles OAuth initiate endpoints", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    const googleRes = await app.request("/api/oauth/google/initiate", { method: "POST" });
    expect(googleRes.status).toBe(200);
    const googleJson = (await googleRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(googleJson.success).toBe(true);
    expect(googleJson.data.authUrl).toContain("accounts.google.com");

    const claudeRes = await app.request("/api/oauth/claude/initiate", { method: "POST" });
    expect(claudeRes.status).toBe(200);
    const claudeJson = (await claudeRes.json()) as { success: boolean; data: { authUrl: string } };
    expect(claudeJson.success).toBe(true);
    expect(claudeJson.data.authUrl).toContain("claude.ai");

    vault.close();
  });
});

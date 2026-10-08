import { describe, expect, it } from "bun:test";
import { CopilotAdapter } from "../src/core/providers/copilot";
import { CursorAdapter } from "../src/core/providers/cursor";
import { XaiAdapter } from "../src/core/providers/xai";
import { ZaiAdapter } from "../src/core/providers/zai";
import type { StoredCredential } from "../src/types";

const mockCred: StoredCredential = {
  id: "test-provider-1",
  ownerId: "test-owner",
  provider: "copilot",
  accountLabel: "Test Provider",
  credentialType: "oauth",
  secret: "mock-secret-token",
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

describe("CopilotAdapter", () => {
  it("parses quota_snapshots for premium and chat", async () => {
    const adapter = new CopilotAdapter();
    expect(adapter.supports("github-copilot")).toBe(true);
    expect(adapter.supports("copilot")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          copilot_plan: "individual",
          quota_reset_date: "2026-10-01",
          quota_snapshots: {
            premium_interactions: {
              entitlement: 200,
              quota_remaining: 180,
              percent_remaining: 90,
            },
            chat: {
              percent_remaining: 100,
              unlimited: true,
            },
          },
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("GitHub Copilot");
    expect(report.limits.length).toBe(2);

    const premium = report.limits.find(l => l.id === "premium_interactions");
    expect(premium?.amount.used).toBe(10);
    expect(premium?.amount.remaining).toBe(90);
    expect(premium?.status).toBe("ok");

    const chat = report.limits.find(l => l.id === "chat_quota");
    expect(chat?.amount.remaining).toBe(100);
  });
});

describe("CursorAdapter", () => {
  it("parses gpt-4 fast request usage", async () => {
    const adapter = new CursorAdapter();
    expect(adapter.supports("cursor")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          "gpt-4": {
            numRequests: 120,
            maxRequestUsage: 500,
          },
          startOfMonth: "2026-09-01T00:00:00.000Z",
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage({ ...mockCred, provider: "cursor" }, { fetch: mockFetch });
    expect(report.provider).toBe("Cursor");
    expect(report.limits.length).toBe(1);

    const fast = report.limits[0];
    expect(fast?.amount.used).toBe(24); // 120 / 500 * 100
    expect(fast?.amount.remaining).toBe(76);
    expect(fast?.status).toBe("ok");
  });
});

describe("XaiAdapter", () => {
  it("parses grok billing credit usage", async () => {
    const adapter = new XaiAdapter();
    expect(adapter.supports("xai-oauth")).toBe(true);
    expect(adapter.supports("grok")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          creditUsagePercent: 15,
          currentPeriod: {
            end: "2026-09-20T00:00:00Z",
          },
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage({ ...mockCred, provider: "xai-oauth" }, { fetch: mockFetch });
    expect(report.provider).toBe("xAI (Grok)");
    expect(report.limits.length).toBe(1);
    expect(report.limits[0]?.amount.used).toBe(15);
    expect(report.limits[0]?.amount.remaining).toBe(85);
  });
  it("refreshes a rejected OAuth token and persists rotated tokens before retrying", async () => {
    const adapter = new XaiAdapter();
    const credential: StoredCredential = {
      ...mockCred,
      provider: "xai-oauth",
      credentialType: "oauth",
      secret: "expired-access-token",
      metadata: { refreshToken: "old-refresh-token" },
    };
    const signal = new AbortController().signal;
    const events: string[] = [];
    let persisted: { secret: string; metadata?: Record<string, unknown> } | undefined;
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = input.toString();
      expect(init?.signal).toBe(signal);

      if (url === "https://auth.x.ai/oauth2/token") {
        events.push("refresh");
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("Content-Type")).toBe("application/x-www-form-urlencoded");
        const body = new URLSearchParams(String(init?.body));
        expect(body.get("grant_type")).toBe("refresh_token");
        expect(body.get("client_id")).toBe("b1a00492-073a-47ea-816f-4c329264a828");
        expect(body.get("refresh_token")).toBe("old-refresh-token");
        return new Response(JSON.stringify({ access_token: "fresh-access-token", refresh_token: "fresh-refresh-token" }));
      }

      const authorization = new Headers(init?.headers).get("Authorization");
      events.push(`usage:${authorization}`);
      if (authorization === "Bearer expired-access-token") {
        return new Response(null, { status: 401 });
      }
      return new Response(JSON.stringify({
        creditUsagePercent: 15,
        currentPeriod: { end: "2026-10-20T00:00:00Z" },
      }));
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(credential, {
      fetch: mockFetch,
      signal,
      onTokenRefresh: (secret, metadata) => {
        events.push("persist");
        persisted = { secret, metadata };
      },
    });

    expect(events).toEqual([
      "usage:Bearer expired-access-token",
      "refresh",
      "persist",
      "usage:Bearer fresh-access-token",
    ]);
    expect(persisted).toEqual({ secret: "fresh-access-token", metadata: { refreshToken: "fresh-refresh-token" } });
    expect(credential.secret).toBe("fresh-access-token");
    expect(credential.metadata?.["refreshToken"]).toBe("fresh-refresh-token");
    expect(report.limits[0]?.amount.used).toBe(15);
  });

  it("retries a refreshed token only once and retains the prior refresh token when rotation is omitted", async () => {
    const adapter = new XaiAdapter();
    const credential: StoredCredential = {
      ...mockCred,
      provider: "xai-oauth",
      credentialType: "oauth",
      secret: "expired-access-token",
      metadata: { refreshToken: "retained-refresh-token" },
    };
    let usageCalls = 0;
    let refreshCalls = 0;
    let persisted: { secret: string; metadata?: Record<string, unknown> } | undefined;
    const mockFetch = (async (input: string | URL | Request) => {
      if (input.toString() === "https://auth.x.ai/oauth2/token") {
        refreshCalls++;
        return new Response(JSON.stringify({ access_token: "fresh-access-token" }));
      }
      usageCalls++;
      return new Response(null, { status: 401 });
    }) as unknown as typeof fetch;

    await expect(adapter.fetchUsage(credential, {
      fetch: mockFetch,
      onTokenRefresh: (secret, metadata) => { persisted = { secret, metadata }; },
    })).rejects.toThrow("HTTP 401");

    expect(usageCalls).toBe(2);
    expect(refreshCalls).toBe(1);
    expect(persisted).toEqual({ secret: "fresh-access-token", metadata: { refreshToken: "retained-refresh-token" } });
    expect(credential.secret).toBe("fresh-access-token");
    expect(credential.metadata?.["refreshToken"]).toBe("retained-refresh-token");
  });

  it("does not refresh on a 403 or a 401 without a nonempty refresh token", async () => {
    const adapter = new XaiAdapter();
    for (const scenario of [
      { status: 401, metadata: undefined },
      { status: 401, metadata: { refreshToken: "  " } },
      { status: 403, metadata: { refreshToken: "unused-refresh-token" } },
    ]) {
      let calls = 0;
      const mockFetch = (async () => {
        calls++;
        return new Response(null, { status: scenario.status });
      }) as unknown as typeof fetch;
      const credential: StoredCredential = {
        ...mockCred,
        provider: "xai-oauth",
        credentialType: "oauth",
        secret: "access-token",
        metadata: scenario.metadata,
      };

      await expect(adapter.fetchUsage(credential, { fetch: mockFetch })).rejects.toThrow(`HTTP ${scenario.status}`);
      expect(calls).toBe(1);
    }
  });

  it("surfaces sanitized refresh failures without retrying the usage request", async () => {
    const adapter = new XaiAdapter();
    let usageCalls = 0;
    let refreshCalls = 0;
    const mockFetch = (async (input: string | URL | Request) => {
      if (input.toString() === "https://auth.x.ai/oauth2/token") {
        refreshCalls++;
        return new Response("private-refresh-response-body", { status: 400 });
      }
      usageCalls++;
      return new Response(null, { status: 401 });
    }) as unknown as typeof fetch;
    const credential: StoredCredential = {
      ...mockCred,
      provider: "xai-oauth",
      credentialType: "oauth",
      secret: "private-access-token",
      metadata: { refreshToken: "private-refresh-token" },
    };

    const error = await adapter.fetchUsage(credential, { fetch: mockFetch }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    if (error instanceof Error) {
      expect(error.message).toBe("xAI usage returned HTTP 401; OAuth token refresh failed.");
      expect(error.message).not.toContain("private-refresh-response-body");
      expect(error.message).not.toContain("private-access-token");
      expect(error.message).not.toContain("private-refresh-token");
    }
    expect(usageCalls).toBe(1);
    expect(refreshCalls).toBe(1);
  });

  it("passes cancellation to the refresh request and stops before retrying", async () => {
    const adapter = new XaiAdapter();
    const controller = new AbortController();
    let usageCalls = 0;
    let refreshCalls = 0;
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (input.toString() === "https://auth.x.ai/oauth2/token") {
        refreshCalls++;
        expect(init?.signal).toBe(controller.signal);
        controller.abort();
        throw new DOMException("The operation was aborted", "AbortError");
      }
      usageCalls++;
      expect(init?.signal).toBe(controller.signal);
      return new Response(null, { status: 401 });
    }) as unknown as typeof fetch;
    const credential: StoredCredential = {
      ...mockCred,
      provider: "xai-oauth",
      credentialType: "oauth",
      secret: "access-token",
      metadata: { refreshToken: "refresh-token" },
    };

    const error = await adapter.fetchUsage(credential, { fetch: mockFetch, signal: controller.signal })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ name: "AbortError" });
    expect(usageCalls).toBe(1);
    expect(refreshCalls).toBe(1);
  });
});

describe("ZaiAdapter", () => {
  it("parses Zhipu GLM monitor quota", async () => {
    const adapter = new ZaiAdapter();
    expect(adapter.supports("zai")).toBe(true);
    expect(adapter.supports("glm")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          data: {
            level: "pro",
            limits: [
              {
                type: "Coding",
                percentage: 45,
                nextResetTime: Date.now() + 3600 * 1000,
              },
            ],
          },
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage({ ...mockCred, provider: "zai" }, { fetch: mockFetch });
    expect(report.provider).toBe("Zhipu AI (GLM)");
    expect(report.limits.length).toBe(1);
    expect(report.limits[0]?.amount.used).toBe(45);
    expect(report.limits[0]?.notes?.[0]).toBe("Plan: pro");
  });
});

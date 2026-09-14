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

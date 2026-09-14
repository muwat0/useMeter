import { describe, expect, it } from "bun:test";
import { DeepSeekAdapter } from "../src/core/providers/deepseek";
import { OpenRouterAdapter } from "../src/core/providers/openrouter";
import { ClaudeAdapter } from "../src/core/providers/claude";
import { CodexAdapter } from "../src/core/providers/codex";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { StorageVault } from "../src/core/storage/vault";
import type { StoredCredential } from "../src/types";

const mockCred: StoredCredential = {
  id: "test-cred-1",
  ownerId: "test-owner",
  provider: "deepseek",
  accountLabel: "Test Account",
  credentialType: "api_key",
  secret: "sk-mock-secret",
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

describe("DeepSeekAdapter", () => {
  it("parses balance response into USD limits", async () => {
    const adapter = new DeepSeekAdapter();
    expect(adapter.supports("deepseek")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          is_available: true,
          balance_infos: [
            {
              currency: "USD",
              total_balance: "42.50",
              granted_balance: "2.50",
              topped_up_balance: "40.00",
            },
          ],
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("deepseek");
    expect(report.limits.length).toBe(1);
    expect(report.limits[0]?.amount.remaining).toBe(42.5);
    expect(report.limits[0]?.status).toBe("ok");
  });
});

describe("OpenRouterAdapter", () => {
  it("parses auth/key and credits responses", async () => {
    const adapter = new OpenRouterAdapter();
    expect(adapter.supports("openrouter")).toBe(true);

    const mockFetch = (async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("/auth/key")) {
        return new Response(
          JSON.stringify({
            data: {
              label: "Production Key",
              usage: 15.5,
              limit: 50.0,
              limit_remaining: 34.5,
              is_free_tier: false,
              rate_limit: { requests: 20, interval: "10s" },
            },
          }),
        );
      }
      if (urlStr.includes("/credits")) {
        return new Response(
          JSON.stringify({
            data: {
              total_credits: 100.0,
              total_usage: 15.5,
            },
          }),
        );
      }
      return new Response("Not found", { status: 404 });
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage({ ...mockCred, provider: "openrouter" }, { fetch: mockFetch });
    expect(report.provider).toBe("openrouter");
    expect(report.limits.length).toBe(3); // account balance, key usage, rate limit

    const accountLimit = report.limits.find(l => l.id === "account_balance");
    expect(accountLimit?.amount.remaining).toBe(84.5);
    expect(accountLimit?.status).toBe("ok");
  });
});

describe("ClaudeAdapter", () => {
  it("parses oauth usage response and header limits", async () => {
    const adapter = new ClaudeAdapter();
    expect(adapter.supports("anthropic")).toBe(true);
    expect(adapter.supports("claude")).toBe(true);

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          five_hour: {
            utilization: 45.0,
            resets_at: new Date(Date.now() + 3600 * 1000).toISOString(),
          },
          seven_day: {
            utilization: 60.0,
            resets_at: new Date(Date.now() + 86400 * 1000).toISOString(),
          },
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage({ ...mockCred, provider: "anthropic" }, { fetch: mockFetch });
    expect(report.limits.length).toBe(2);

    const fiveHour = report.limits.find(l => l.id === "5h");
    expect(fiveHour?.amount.used).toBe(45);
    expect(fiveHour?.amount.remaining).toBe(55);
    expect(fiveHour?.status).toBe("ok");

    // Test header parsing
    const headers = new Headers({
      "anthropic-ratelimit-unified-5h-utilization": "0.95",
      "anthropic-ratelimit-unified-5h-reset": "1726240000",
    });
    const headerReport = adapter.parseHeaders(headers);
    expect(headerReport).not.toBeNull();
    expect(headerReport?.limits[0]?.amount.used).toBe(95);
  });
});

describe("CodexAdapter", () => {
  it("parses wham usage and rate limit reset credits", async () => {
    const adapter = new CodexAdapter();
    expect(adapter.supports("openai-codex")).toBe(true);

    const mockFetch = (async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("rate-limit-reset-credits")) {
        return new Response(
          JSON.stringify({
            available_count: 1,
            credits: [
              {
                id: "credit_1",
                status: "available",
                title: "Full reset (Weekly + 5 hr)",
                expires_at: "2026-10-05T00:00:00Z",
              },
            ],
          }),
        );
      }
      return new Response(
        JSON.stringify({
          plan_type: "plus",
          rate_limit: {
            allowed: true,
            limit_reached: false,
            primary_window: {
              used_percent: 20,
              limit_window_seconds: 18000,
              reset_after_seconds: 14400,
            },
          },
        }),
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage({ ...mockCred, provider: "openai-codex" }, { fetch: mockFetch });
    expect(report.limits.length).toBe(2);

    const primaryLimit = report.limits.find(l => l.id === "primary_window");
    expect(primaryLimit?.amount.used).toBe(20);
    expect(primaryLimit?.status).toBe("ok");

    const resetLimit = report.limits.find(l => l.id === "reset_credits");
    expect(resetLimit?.amount.remaining).toBe(1);
    expect(resetLimit?.status).toBe("ok");
    expect(resetLimit?.notes?.[0]).toBe("Full reset (Weekly + 5 hr)");
    // Test header parsing
    const headers = new Headers({
      "x-codex-primary-used-percent": "100",
      "x-codex-primary-reset-after-seconds": "1800",
    });
    const headerReport = adapter.parseHeaders(headers);
    expect(headerReport).not.toBeNull();
    expect(headerReport?.limits[0]?.status).toBe("exhausted");
  });
});
describe("PollerEngine", () => {
  it("polls registered credentials and notifies listeners", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller@example.com", "hash");
    const saved = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Poller Test",
      credentialType: "api_key",
      secret: "sk-mock",
    });

    const registry = new ProviderRegistry();
    const adapter = new DeepSeekAdapter();
    registry.register(adapter);
    const poller = new PollerEngine(vault, registry);
    let notified = false;
    poller.onReport(r => {
      if (r.credentialId === saved.id && r.ownerId === owner.id) notified = true;
    });
    adapter.fetchUsage = async cred => ({
      ownerId: cred.ownerId,
      provider: cred.provider,
      credentialId: cred.id,
      accountLabel: cred.accountLabel,
      fetchedAt: Date.now(),
      limits: [{ id: "balance", label: "Test Balance", amount: { remaining: 50, unit: "usd" }, status: "ok" }],
    });

    const reports = await poller.pollUser(owner.id);
    expect(reports.length).toBe(1);
    expect(notified).toBe(true);
    const latest = vault.getLatestUsage(owner.id);
    expect(latest.length).toBe(1);
    expect(latest[0]?.limits[0]?.amount.remaining).toBe(50);
    expect(await poller.pollCredential("foreign-owner", saved.id)).toBeNull();
    vault.close();
  });
});

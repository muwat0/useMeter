import { describe, expect, it } from "bun:test";
import { DeepSeekAdapter } from "../src/core/providers/deepseek";
import { OpenRouterAdapter } from "../src/core/providers/openrouter";
import { ClaudeAdapter } from "../src/core/providers/claude";
import { CodexAdapter } from "../src/core/providers/codex";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { StorageVault } from "../src/core/storage/vault";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import type { StoredCredential, UsageReport } from "../src/types";

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
  it("refreshes a rejected OAuth token and persists rotated tokens before retrying", async () => {
    const adapter = new CodexAdapter();
    const credential: StoredCredential = {
      ...mockCred,
      provider: "openai-codex",
      credentialType: "oauth",
      secret: "expired-access-token",
      metadata: { accountId: "codex-account", refreshToken: "old-refresh-token" },
    };
    const signal = new AbortController().signal;
    const events: string[] = [];
    let persisted: { secret: string; metadata?: Record<string, unknown> } | undefined;
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = input.toString();
      expect(init?.signal).toBe(signal);

      if (url === "https://auth.openai.com/oauth/token") {
        events.push("refresh");
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("Content-Type")).toBe("application/x-www-form-urlencoded");
        const body = new URLSearchParams(String(init?.body));
        expect(body.get("grant_type")).toBe("refresh_token");
        expect(body.get("client_id")).toBe("app_EMoamEEZ73f0CkXaXp7hrann");
        expect(body.get("refresh_token")).toBe("old-refresh-token");
        return new Response(JSON.stringify({ access_token: "fresh-access-token", refresh_token: "fresh-refresh-token" }));
      }

      if (url.endsWith("/usage")) {
        const authorization = new Headers(init?.headers).get("Authorization");
        events.push(`usage:${authorization}`);
        expect(new Headers(init?.headers).get("chatgpt-account-id")).toBe("codex-account");
        if (authorization === "Bearer expired-access-token") {
          return new Response(null, { status: 401, statusText: "Unauthorized" });
        }
        return new Response(JSON.stringify({
          plan_type: "plus",
          rate_limit: { primary_window: { used_percent: 25 } },
        }));
      }

      expect(url).toContain("rate-limit-reset-credits");
      events.push("credits");
      return new Response(JSON.stringify({ available_count: 0 }));
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
      "credits",
    ]);
    expect(persisted).toEqual({ secret: "fresh-access-token", metadata: { refreshToken: "fresh-refresh-token" } });
    expect(credential.secret).toBe("fresh-access-token");
    expect(credential.metadata?.["refreshToken"]).toBe("fresh-refresh-token");
    expect(report.limits.find(limit => limit.id === "primary_window")?.amount.used).toBe(25);
  });

  it("retries a refreshed token only once and retains the prior refresh token when rotation is omitted", async () => {
    const adapter = new CodexAdapter();
    const credential: StoredCredential = {
      ...mockCred,
      provider: "openai-codex",
      credentialType: "oauth",
      secret: "expired-access-token",
      metadata: { refreshToken: "retained-refresh-token" },
    };
    let usageCalls = 0;
    let refreshCalls = 0;
    let persisted: { secret: string; metadata?: Record<string, unknown> } | undefined;
    const mockFetch = (async (input: string | URL | Request) => {
      if (input.toString() === "https://auth.openai.com/oauth/token") {
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
    const adapter = new CodexAdapter();
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
        provider: "openai-codex",
        credentialType: "oauth",
        secret: "access-token",
        metadata: scenario.metadata,
      };

      await expect(adapter.fetchUsage(credential, { fetch: mockFetch })).rejects.toThrow(`HTTP ${scenario.status}`);
      expect(calls).toBe(1);
    }
  });

  it("surfaces sanitized refresh failures without retrying the usage request", async () => {
    const adapter = new CodexAdapter();
    let usageCalls = 0;
    let refreshCalls = 0;
    const mockFetch = (async (input: string | URL | Request) => {
      if (input.toString() === "https://auth.openai.com/oauth/token") {
        refreshCalls++;
        return new Response("private-refresh-response-body", { status: 400 });
      }
      usageCalls++;
      return new Response(null, { status: 401 });
    }) as unknown as typeof fetch;
    const credential: StoredCredential = {
      ...mockCred,
      provider: "openai-codex",
      credentialType: "oauth",
      secret: "private-access-token",
      metadata: { refreshToken: "private-refresh-token" },
    };

    const error = await adapter.fetchUsage(credential, { fetch: mockFetch }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    if (error instanceof Error) {
      expect(error.message).toBe("Codex usage returned HTTP 401; OAuth token refresh failed.");
      expect(error.message).not.toContain("private-refresh-response-body");
      expect(error.message).not.toContain("private-access-token");
      expect(error.message).not.toContain("private-refresh-token");
    }
    expect(usageCalls).toBe(1);
    expect(refreshCalls).toBe(1);
  });
  it("passes cancellation to the refresh request and stops before retrying", async () => {
    const adapter = new CodexAdapter();
    const controller = new AbortController();
    let usageCalls = 0;
    let refreshCalls = 0;
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (input.toString() === "https://auth.openai.com/oauth/token") {
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
      provider: "openai-codex",
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
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
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

  it("reloads queued daemon credentials after reauthorization before provider dispatch", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("queued-poll@example.com", "hash");
    const first = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Blocker",
      credentialType: "api_key",
      secret: "blocker-secret",
    });
    const queued = vault.saveCredential(owner.id, {
      provider: "openrouter",
      accountLabel: "Reauthorized",
      credentialType: "oauth",
      secret: "old-access",
      metadata: { refreshToken: "old-refresh" },
    });
    const blockerStarted = Promise.withResolvers<void>();
    const releaseBlocker = Promise.withResolvers<void>();
    const targetRequests: Array<{ requestSecret: string; persistedSecret: string | undefined }> = [];
    const registry = new ProviderRegistry();
    const fetchUsage: ProviderAdapter["fetchUsage"] = async (credential, ctx) => {
      if (credential.id === first.id) {
        blockerStarted.resolve();
        await releaseBlocker.promise;
      } else {
        targetRequests.push({
          requestSecret: credential.secret,
          persistedSecret: vault.getCredential(owner.id, queued.id)?.secret,
        });
        if (credential.secret !== "new-access") {
          ctx?.onTokenRefresh?.("stale-access", { refreshToken: "stale-refresh" });
        }
      }
      return {
        ownerId: credential.ownerId,
        provider: credential.provider,
        credentialId: credential.id,
        accountLabel: credential.accountLabel,
        fetchedAt: Date.now(),
        limits: [],
        health: "healthy",
        source: "live",
      };
    };
    registry.register({
      id: "queued-poll-test-deepseek",
      supports: provider => provider === "deepseek",
      fetchUsage,
    });
    registry.register({
      id: "queued-poll-test-openrouter",
      supports: provider => provider === "openrouter",
      fetchUsage,
    });
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
    });
    let blockerPoll: Promise<UsageReport | null> | undefined;
    let validation: Promise<StoredCredential> | undefined;
    let sweep: Promise<UsageReport[]> | undefined;

    try {
      blockerPoll = poller.pollCredential(owner.id, first.id);
      await blockerStarted.promise;
      validation = poller.validateAndSaveCredential(owner.id, {
        provider: "openrouter",
        accountLabel: "Reauthorized",
        credentialType: "oauth",
        secret: "new-access",
        metadata: { refreshToken: "new-refresh" },
      }, "preserve");
      sweep = poller.pollAll();

      releaseBlocker.resolve();
      await blockerPoll;
      const saved = await validation;
      expect(saved.id).toBe(queued.id);
      const reports = await sweep;

      expect(targetRequests).toEqual([
        { requestSecret: "new-access", persistedSecret: "old-access" },
        { requestSecret: "new-access", persistedSecret: "new-access" },
      ]);
      expect(reports.map(report => report.credentialId)).toEqual([first.id, queued.id]);
      expect(reports.some(report => report.error || report.stale)).toBe(false);
      expect(vault.getCredential(owner.id, queued.id)).toMatchObject({
        secret: "new-access",
        metadata: { refreshToken: "new-refresh" },
      });
    } finally {
      releaseBlocker.resolve();
      if (blockerPoll) await blockerPoll.catch(() => {});
      if (validation) await validation.catch(() => {});
      if (sweep) await sweep.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("skips a queued user credential deleted before dispatch", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deleted-queued-poll@example.com", "hash");
    const first = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Blocker",
      credentialType: "api_key",
      secret: "blocker-secret",
    });
    const queued = vault.saveCredential(owner.id, {
      provider: "openrouter",
      accountLabel: "Deleted",
      credentialType: "oauth",
      secret: "deleted-access",
    });
    const blockerStarted = Promise.withResolvers<void>();
    const releaseBlocker = Promise.withResolvers<void>();
    const fetchedIds: string[] = [];
    const registry = new ProviderRegistry();
    registry.register({
      id: "deleted-queued-poll-test",
      supports: provider => provider === "deepseek" || provider === "openrouter",
      fetchUsage: async (credential: StoredCredential): Promise<UsageReport> => {
        fetchedIds.push(credential.id);
        if (credential.id === first.id) {
          blockerStarted.resolve();
          await releaseBlocker.promise;
        }
        return {
          ownerId: credential.ownerId,
          provider: credential.provider,
          credentialId: credential.id,
          accountLabel: credential.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          source: "live",
        };
      },
    });
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    let polling: Promise<UsageReport[]> | undefined;

    try {
      polling = poller.pollUser(owner.id);
      await blockerStarted.promise;
      vault.deleteCredential(owner.id, queued.id);
      releaseBlocker.resolve();
      const reports = await polling;
      expect(fetchedIds).toEqual([first.id]);
      expect(reports.map(report => report.credentialId)).toEqual([first.id]);
      expect(vault.getCredential(owner.id, queued.id)).toBeNull();
    } finally {
      releaseBlocker.resolve();
      if (polling) await polling;
      poller.stop();
      vault.close();
    }
  });
});

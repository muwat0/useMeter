import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";
import type { UsageReport } from "../src/types";
import type { ProviderAdapter } from "../src/core/providers/adapter";

describe("Stale Dashboard SSR and Client Telemetry", () => {
  it("renders dashboard HTML preserving stale indicators, cached limits, error states, and exhausted quota without fabrication", async () => {
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register authenticated owner
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "owner@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = vault.getUserByEmail("owner@example.com");
    expect(user).not.toBeNull();
    const ownerId = user!.id;

    // 1. Seed Healthy credential & report
    const credHealthy = vault.saveCredential(ownerId, {
      provider: "deepseek",
      accountLabel: "Prod-DeepSeek-Key",
      credentialType: "api_key",
      secret: "sk-healthy",
      accent: "emerald",
    });
    const healthyReport: UsageReport = {
      ownerId,
      provider: "deepseek",
      credentialId: credHealthy.id,
      accountLabel: "Prod-DeepSeek-Key",
      fetchedAt: Date.now() - 30000,
      health: "healthy",
      stale: false,
      source: "live",
      lastGoodFetchedAt: Date.now() - 30000,
      limits: [
        {
          id: "balance",
          label: "API Balance",
          amount: { remaining: 50.0, unit: "usd" },
          status: "ok",
        },
      ],
      raw: { secretPayload: "leak-check-healthy" },
    };
    vault.saveUsageSnapshot(ownerId, healthyReport);

    // 2. Seed Stale credential & report with retained limits and transport error
    const credStale = vault.saveCredential(ownerId, {
      provider: "openrouter",
      accountLabel: "Stale-OpenRouter-Key",
      credentialType: "api_key",
      secret: "sk-stale",
      accent: "amber",
    });
    const staleReport: UsageReport = {
      ownerId,
      provider: "openrouter",
      credentialId: credStale.id,
      accountLabel: "Stale-OpenRouter-Key",
      fetchedAt: Date.now() - 10000,
      health: "stale",
      stale: true,
      source: "stale",
      lastGoodFetchedAt: 1700000000000,
      error: "HTTP 429 Rate limit exceeded. Try again in 60s",
      limits: [
        {
          id: "daily_quota",
          label: "Daily Request Quota",
          amount: { used: 75, limit: 100, remaining: 25, usedFraction: 0.75, unit: "percent" },
          status: "warning",
        },
      ],
      raw: { internalTrace: "leak-check-stale" },
    };
    vault.saveUsageSnapshot(ownerId, staleReport);

    // 3. Seed First-Ever Error credential & report (never succeeded, empty limits)
    const credError = vault.saveCredential(ownerId, {
      provider: "claude",
      accountLabel: "Broken-Claude-Key",
      credentialType: "api_key",
      secret: "sk-broken",
      accent: "slate",
    });
    const firstErrorReport: UsageReport = {
      ownerId,
      provider: "claude",
      credentialId: credError.id,
      accountLabel: "Broken-Claude-Key",
      fetchedAt: Date.now() - 5000,
      health: "error",
      stale: false,
      source: "error",
      error: "401 Unauthorized: Invalid API key",
      limits: [],
      raw: { sensitiveAuth: "leak-check-error" },
    };
    vault.saveUsageSnapshot(ownerId, firstErrorReport);

    // 4. Seed Genuine Exhausted credential & report (healthy telemetry at 100% usage)
    const credExhausted = vault.saveCredential(ownerId, {
      provider: "codex",
      accountLabel: "Exhausted-Codex-Plan",
      credentialType: "oauth",
      secret: "tok-exhausted",
      accent: "violet",
    });
    const exhaustedReport: UsageReport = {
      ownerId,
      provider: "codex",
      credentialId: credExhausted.id,
      accountLabel: "Exhausted-Codex-Plan",
      fetchedAt: Date.now() - 20000,
      health: "healthy",
      stale: false,
      source: "live",
      lastGoodFetchedAt: Date.now() - 20000,
      limits: [
        {
          id: "5h_quota",
          label: "5-Hour Session Quota",
          amount: { used: 100, limit: 100, usedFraction: 1.0, remaining: 0, unit: "percent" },
          status: "exhausted",
        },
      ],
      raw: { authTokens: "leak-check-exhausted" },
    };
    vault.saveUsageSnapshot(ownerId, exhaustedReport);

    // React dashboard receives report telemetry through the sanitized bootstrap payload.
    const htmlRes = await app.request("/", { headers: { Cookie: cookie } });
    expect(htmlRes.status).toBe(200);
    const html = await htmlRes.text();
    expect(html).toContain('id="app"');
    const bootstrapMatch = html.match(/<script id="usemeter-bootstrap"[^>]*>([\s\S]*?)<\/script>/);
    expect(bootstrapMatch).not.toBeNull();
    const bootstrap = JSON.parse(bootstrapMatch![1]!) as { reports: UsageReport[] };
    expect(bootstrap.reports.length).toBe(4);
    const stale = bootstrap.reports.find(r => r.credentialId === credStale.id)!;
    const broken = bootstrap.reports.find(r => r.credentialId === credError.id)!;
    const exhausted = bootstrap.reports.find(r => r.credentialId === credExhausted.id)!;
    expect(stale.health).toBe("stale");
    expect(stale.stale).toBe(true);
    expect(stale.limits[0]?.amount.used).toBe(75);
    expect(stale.error).toContain("429");
    expect(broken.health).toBe("error");
    expect(broken.limits).toHaveLength(0);
    expect(exhausted.limits[0]?.status).toBe("exhausted");
    expect(exhausted.limits[0]?.amount.used).toBe(100);
    expect(exhausted.health).not.toBe("stale");
  });

  it("serves /api/data and /api/usage retaining stale metadata while strictly stripping raw payloads", async () => {
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register authenticated owner
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "apitester@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = vault.getUserByEmail("apitester@example.com");
    const ownerId = user!.id;

    // Seed Stale Credential and Report
    const credStale = vault.saveCredential(ownerId, {
      provider: "openrouter",
      accountLabel: "API-Stale-Key",
      credentialType: "api_key",
      secret: "sk-api-stale",
    });
    const staleReport: UsageReport = {
      ownerId,
      provider: "openrouter",
      credentialId: credStale.id,
      accountLabel: "API-Stale-Key",
      fetchedAt: 1700000020000,
      health: "stale",
      stale: true,
      source: "stale",
      lastGoodFetchedAt: 1700000000000,
      error: "502 Bad Gateway from upstream provider",
      limits: [
        {
          id: "tokens",
          label: "Monthly Token Limit",
          amount: { used: 500000, limit: 1000000, remaining: 500000, unit: "tokens" },
          status: "ok",
        },
      ],
      raw: { superSecretToken: "raw-secret-stale-token" },
    };
    vault.saveUsageSnapshot(ownerId, staleReport);

    // Seed First Error Credential and Report
    const credError = vault.saveCredential(ownerId, {
      provider: "claude",
      accountLabel: "API-Error-Key",
      credentialType: "api_key",
      secret: "sk-api-error",
    });
    const errorReport: UsageReport = {
      ownerId,
      provider: "claude",
      credentialId: credError.id,
      accountLabel: "API-Error-Key",
      fetchedAt: 1700000025000,
      health: "error",
      stale: false,
      source: "error",
      error: "DNS lookup failed for api.anthropic.com",
      limits: [],
      raw: { internalSocketDetails: "raw-socket-leak" },
    };
    vault.saveUsageSnapshot(ownerId, errorReport);

    // Exercise GET /api/data
    const dataRes = await app.request("/api/data", {
      headers: { Cookie: cookie },
    });
    expect(dataRes.status).toBe(200);
    const dataJson = (await dataRes.json()) as { success: boolean; data: UsageReport[] };
    expect(dataJson.success).toBe(true);
    expect(Array.isArray(dataJson.data)).toBe(true);

    const staleItem = dataJson.data.find(r => r.credentialId === credStale.id);
    expect(staleItem).toBeDefined();
    expect(staleItem?.health).toBe("stale");
    expect(staleItem?.stale).toBe(true);
    expect(staleItem?.source).toBe("stale");
    expect(staleItem?.lastGoodFetchedAt).toBe(1700000000000);
    expect(staleItem?.error).toBe("502 Bad Gateway from upstream provider");
    expect(staleItem?.limits.length).toBe(1);
    expect(staleItem?.limits[0]?.label).toBe("Monthly Token Limit");
    expect(staleItem?.limits[0]?.amount.remaining).toBe(500000);

    const errorItem = dataJson.data.find(r => r.credentialId === credError.id);
    expect(errorItem).toBeDefined();
    expect(errorItem?.health).toBe("error");
    expect(errorItem?.stale).toBe(false);
    expect(errorItem?.source).toBe("error");
    expect(errorItem?.limits).toEqual([]);
    expect(errorItem?.error).toBe("DNS lookup failed for api.anthropic.com");

    // Exercise GET /api/usage (alias to /api/data)
    const usageRes = await app.request("/api/usage", {
      headers: { Cookie: cookie },
    });
    expect(usageRes.status).toBe(200);
    const usageJson = (await usageRes.json()) as { success: boolean; data: UsageReport[] };
    expect(usageJson.data.length).toBe(dataJson.data.length);

    // Verify raw is stripped and confidential payloads are never exposed
    for (const rep of dataJson.data) {
      expect(rep.raw).toBeUndefined();
    }
    const rawStringified = JSON.stringify(dataJson);
    expect(rawStringified).not.toContain("raw-secret-stale-token");
    expect(rawStringified).not.toContain("raw-socket-leak");

    vault.close();
  });

  it("embeds complete TR and EN localization dictionaries for stale, error, and cached states in dashboard scripts", async () => {
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "i18ntester@example.com", password: "Password12345678!" }),
    });
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;

    const res = await app.request("/", {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const html = await res.text();

    expect(html).toContain('/assets/app.js');
    const clientSource = await Bun.file('src/client/main.tsx').text();
    expect(clientSource).toContain('const I18N');
    expect(clientSource).toContain('Eski Veri');
    expect(clientSource).toContain('Showing cached limits');

    expect(html).not.toContain('</script><script>');
    vault.close();
  });

  it("transitions a live credential to stale with retained limits via PollerEngine and reflects in dashboard", async () => {
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    let shouldFail = false;
    let pollCount = 0;
    const mockAdapter: ProviderAdapter = {
      id: "mockprovider",
      supports: (p: string) => p === "mockprovider",
      async fetchUsage(cred) {
        pollCount++;
        if (shouldFail) throw new Error("Simulated connection timeout (504)");
        return {
          ownerId: cred.ownerId,
          provider: cred.provider,
          credentialId: cred.id,
          accountLabel: cred.accountLabel,
          fetchedAt: 1700000050000,
          limits: [{ id: "credits", label: "Compute Credits", amount: { remaining: 120, unit: "credits" }, status: "ok" }],
        };
      },
    };
    registry.register(mockAdapter);
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "transition@example.com", password: "Password12345678!" }),
    });
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = vault.getUserByEmail("transition@example.com")!;
    const cred = vault.saveCredential(user.id, { provider: "mockprovider", accountLabel: "Dynamic Mock Key", credentialType: "api_key", secret: "sk-mock" });
    shouldFail = false;
    const report1 = await poller.pollCredential(user.id, cred.id);
    expect(report1).not.toBeNull();
    expect(report1?.health).toBe("healthy");
    expect(report1?.stale).toBe(false);
    expect(report1?.source).toBe("live");
    expect(report1?.limits[0]?.amount.remaining).toBe(120);
    const dataRes1 = await app.request("/api/data", { headers: { Cookie: cookie } });
    const dataJson1 = (await dataRes1.json()) as { success: boolean; data: UsageReport[] };
    expect(dataJson1.data[0]?.health).toBe("healthy");
    expect(dataJson1.data[0]?.stale).toBe(false);
    expect(dataJson1.data[0]?.limits[0]?.amount.remaining).toBe(120);
    shouldFail = true;
    const report2 = await poller.pollCredential(user.id, cred.id);
    expect(report2).not.toBeNull();
    expect(report2?.health).toBe("stale");
    expect(report2?.stale).toBe(true);
    expect(report2?.source).toBe("stale");
    expect(report2?.lastGoodFetchedAt).toBe(1700000050000);
    expect(report2?.error).toContain("Simulated connection timeout");
    expect(report2?.limits.length).toBe(1);
    expect(report2?.limits[0]?.label).toBe("Compute Credits");
    expect(report2?.limits[0]?.amount.remaining).toBe(120);
    const dataRes2 = await app.request("/api/data", { headers: { Cookie: cookie } });
    const dataJson2 = (await dataRes2.json()) as { success: boolean; data: UsageReport[] };
    expect(dataJson2.data[0]?.health).toBe("stale");
    expect(dataJson2.data[0]?.stale).toBe(true);
    expect(dataJson2.data[0]?.limits[0]?.amount.remaining).toBe(120);
    expect(dataJson2.data[0]?.error).toContain("Simulated connection timeout");
    const htmlRes2 = await app.request("/", { headers: { Cookie: cookie } });
    const html2 = await htmlRes2.text();
    expect(html2).toContain('id="usemeter-bootstrap"');
    const bootstrapMatch = html2.match(/<script id="usemeter-bootstrap"[^>]*>([\s\S]*?)<\/script>/);
    const boot = JSON.parse(bootstrapMatch![1]!) as { reports: UsageReport[] };
    expect(boot.reports[0]?.accountLabel).toBe("Dynamic Mock Key");
    expect(boot.reports[0]?.limits[0]?.label).toBe("Compute Credits");
    expect(boot.reports[0]?.limits[0]?.amount.remaining).toBe(120);
    expect(boot.reports[0]?.health).toBe("stale");
    expect(boot.reports[0]?.error).toContain("Simulated connection timeout");
    expect(pollCount).toBe(2);
    vault.close();
  });
});

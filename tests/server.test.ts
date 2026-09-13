import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";

describe("Server API Endpoints", () => {
  it("serves health, usage, credentials, and dashboard HTML", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // 1. Health check
    const healthRes = await app.request("/health");
    expect(healthRes.status).toBe(200);
    const healthJson = (await healthRes.json()) as { status: string; integrity: boolean };
    expect(healthJson.status).toBe("ok");
    expect(healthJson.integrity).toBe(true);

    // 2. Add credential
    const addRes = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Test Key",
        credentialType: "api_key",
        secret: "sk-or-v1-super-secret-token",
      }),
    });
    expect(addRes.status).toBe(200);
    const addJson = (await addRes.json()) as { success: boolean; data: { id: string } };
    expect(addJson.success).toBe(true);
    expect(addJson.data.id).toBeDefined();

    // 3. List credentials (masked)
    const listRes = await app.request("/api/credentials");
    expect(listRes.status).toBe(200);
    const listJson = (await listRes.json()) as { success: boolean; data: Array<{ maskedSecret: string }> };
    expect(listJson.data.length).toBe(1);
    expect(listJson.data[0]?.maskedSecret).toBe("sk-o...oken");

    // 4. Usage endpoint
    const usageRes = await app.request("/api/usage");
    expect(usageRes.status).toBe(200);

    // 5. Dashboard HTML
    const htmlRes = await app.request("/");
    expect(htmlRes.status).toBe(200);
    const html = await htmlRes.text();
    expect(html).toContain("AI Usage Tracker");
    expect(html).toContain("Multi-Provider Quota & Balance Hub");

    vault.close();
  });
});

import { describe, expect, it } from "bun:test";
import { createDefaultRegistry } from "../src/core/providers/registry";
import {
  findCatalogEntry,
  getProviderCatalog,
  PROVIDER_CATALOG,
  type ProviderCatalogEntry,
  type ProviderSupportTier,
} from "../src/core/providers/catalog";
import { PollerEngine } from "../src/core/poller/poller";
import { StorageVault } from "../src/core/storage/vault";
import { createServer } from "../src/server/app";

interface ProviderCatalogResponse {
  success: boolean;
  providers: readonly ProviderCatalogEntry[];
}

describe("Provider catalog", () => {
  it("matches every adapter registered by createDefaultRegistry", () => {
    const registry = createDefaultRegistry();
    const catalogIds = getProviderCatalog().map(entry => entry.id).sort();
    const adapterIds = registry.all().map(adapter => adapter.id).sort();

    expect(PROVIDER_CATALOG).toHaveLength(17);
    expect(adapterIds).toHaveLength(17);
    expect(new Set(catalogIds).size).toBe(17);
    expect(catalogIds).toEqual(adapterIds);
  });

  it("reports the exact evidence-tier distribution", () => {
    const counts: Record<ProviderSupportTier, number> = {
      live_verified: 0,
      connection_verified: 0,
      synthetic_only: 0,
    };
    for (const entry of PROVIDER_CATALOG) counts[entry.supportTier] += 1;

    expect(counts).toEqual({ live_verified: 4, connection_verified: 1, synthetic_only: 12 });
    expect(PROVIDER_CATALOG
      .filter(entry => entry.supportTier === "live_verified")
      .map(entry => entry.id)
      .sort()).toEqual(["cursor", "github-copilot", "openai-codex", "xai-oauth"]);
    expect(PROVIDER_CATALOG
      .filter(entry => entry.supportTier === "connection_verified")
      .map(entry => entry.id)).toEqual(["kimi-code"]);
  });

  it("resolves every registry alias to its canonical catalog entry", () => {
    const registry = createDefaultRegistry();

    for (const entry of PROVIDER_CATALOG) {
      expect(findCatalogEntry(entry.id)).toBe(entry);
      for (const alias of entry.aliases) {
        expect(findCatalogEntry(alias)).toBe(entry);
        expect(registry.find(alias)?.id).toBe(entry.id);
      }
    }
    expect(findCatalogEntry("  COPILOT ")).toBe(findCatalogEntry("github-copilot"));
    expect(findCatalogEntry("unregistered-provider")).toBeUndefined();
  });

  it("serves the canonical matrix publicly without credential fields", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    try {
      const response = await app.request("/api/providers/catalog");
      expect(response.status).toBe(200);
      const body = await response.json() as ProviderCatalogResponse;
      expect(body).toEqual({ success: true, providers: PROVIDER_CATALOG });
      expect(body.success).toBe(true);
      expect(body.providers).toHaveLength(17);
      for (const provider of body.providers) {
        expect(provider).not.toHaveProperty("secret");
        expect(provider).not.toHaveProperty("token");
        expect(provider).not.toHaveProperty("refreshToken");
        expect(provider).not.toHaveProperty("clientSecret");
      }
    } finally {
      vault.close();
    }
  });
});

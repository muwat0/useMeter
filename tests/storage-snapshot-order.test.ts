import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";
import type { UsageReport } from "../src/types";

describe("snapshot ordering at equal fetch times", () => {
  it("returns the newest same-time healthy snapshot through storage and the consumer API", async () => {
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);
    const register = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "snapshot-order@example.com", password: "Password12345678!" }),
    });
    expect(register.status).toBe(201);
    const cookie = register.headers.get("Set-Cookie")!.split(";")[0]!;
    const owner = vault.getUserByEmail("snapshot-order@example.com")!;
    const otherOwner = vault.createUser("other-snapshot-order@example.com", "passwordhash");
    const credential = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Primary",
      credentialType: "api_key",
      secret: "secret",
    });
    const otherCredential = vault.saveCredential(otherOwner.id, {
      provider: "deepseek",
      accountLabel: "Other",
      credentialType: "api_key",
      secret: "other-secret",
    });

    const report = (fetchedAt: number, remaining: number, health: "healthy" | "error"): UsageReport => ({
      ownerId: owner.id,
      provider: "deepseek",
      credentialId: credential.id,
      accountLabel: "Primary",
      fetchedAt,
      health,
      stale: health !== "healthy",
      source: health === "healthy" ? "live" : "error",
      error: health === "error" ? "Request timed out" : undefined,
      lastGoodFetchedAt: health === "healthy" ? fetchedAt : undefined,
      limits: health === "healthy"
        ? [{ id: "quota", label: "Quota", amount: { remaining, unit: "tokens" }, status: "ok" }]
        : [],
    });

    const sameTime = 1_800_000_000_000;
    expect(vault.saveUsageSnapshot(owner.id, report(sameTime, 0, "error"))).toBe(true);
    expect(vault.saveUsageSnapshot(owner.id, report(sameTime, 7, "healthy"))).toBe(true);
    expect(vault.saveUsageSnapshot(owner.id, report(sameTime, 11, "healthy"))).toBe(true);
    // A later insert with an older provider timestamp must not replace the newer observation.
    expect(vault.saveUsageSnapshot(owner.id, report(sameTime - 1, 3, "healthy"))).toBe(true);

    const latest = vault.getLatestUsage(owner.id);
    expect(latest).toHaveLength(1);
    expect(latest[0]?.health).toBe("healthy");
    expect(latest[0]?.limits[0]?.amount.remaining).toBe(11);
    expect(latest[0]?.fetchedAt).toBe(sameTime);

    const internalLatest = vault.getLatestUsageInternal().filter(item => item.credentialId === credential.id);
    expect(internalLatest).toHaveLength(1);
    expect(internalLatest[0]?.health).toBe("healthy");
    expect(internalLatest[0]?.limits[0]?.amount.remaining).toBe(11);
    expect(internalLatest[0]?.fetchedAt).toBe(sameTime);

    const lastGood = vault.getLastSuccessfulUsage(owner.id, credential.id);
    expect(lastGood?.health).toBe("healthy");
    expect(lastGood?.limits[0]?.amount.remaining).toBe(11);
    expect(lastGood?.fetchedAt).toBe(sameTime);

    const internalLastGood = vault.getLastSuccessfulUsageInternal(credential.id);
    expect(internalLastGood?.health).toBe("healthy");
    expect(internalLastGood?.limits[0]?.amount.remaining).toBe(11);
    expect(internalLastGood?.fetchedAt).toBe(sameTime);

    expect(vault.getLatestUsage(otherOwner.id)).toHaveLength(0);
    expect(vault.getLastSuccessfulUsage(otherOwner.id, credential.id)).toBeNull();
    expect(vault.getLastSuccessfulUsage(owner.id, otherCredential.id)).toBeNull();

    const response = await app.request("/api/data", { headers: { Cookie: cookie } });
    expect(response.status).toBe(200);
    const payload = (await response.json()) as { success: boolean; data: UsageReport[] };
    expect(payload.success).toBe(true);
    const consumerReport = payload.data.find(item => item.credentialId === credential.id);
    expect(consumerReport?.health).toBe("healthy");
    expect(consumerReport?.stale).toBe(false);
    expect(consumerReport?.fetchedAt).toBe(sameTime);
    expect(consumerReport?.limits[0]?.amount.remaining).toBe(11);
    expect(consumerReport?.error).toBeUndefined();

    vault.close();
  });
});

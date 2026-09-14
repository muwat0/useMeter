import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { DeepSeekAdapter } from "../src/core/providers/deepseek";
import type { UsageReport } from "../src/types";

describe("Stale / Degraded / Last-Good Usage Contract", () => {
  it("marks successful poll as healthy, live, stale=false and records lastGoodFetchedAt", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("user1@example.com", "passwordhash");
    const cred = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Main Key",
      credentialType: "api_key",
      secret: "sk-test",
    });

    const registry = new ProviderRegistry();
    const adapter = new DeepSeekAdapter();
    registry.register(adapter);
    const poller = new PollerEngine(vault, registry);

    const t1 = 1700000000000;
    adapter.fetchUsage = async () => ({
      provider: "deepseek",
      fetchedAt: t1,
      limits: [
        {
          id: "balance",
          label: "Balance",
          amount: { remaining: 25.5, unit: "usd" },
          status: "ok",
        },
      ],
    });

    const report = await poller.pollCredential(owner.id, cred.id);
    expect(report).not.toBeNull();
    expect(report?.health).toBe("healthy");
    expect(report?.stale).toBe(false);
    expect(report?.source).toBe("live");
    expect(report?.lastGoodFetchedAt).toBe(t1);
    expect(report?.limits.length).toBe(1);
    expect(report?.limits[0]?.amount.remaining).toBe(25.5);
    expect(report?.error).toBeUndefined();

    // Verify snapshot in vault
    const lastGood = vault.getLastSuccessfulUsage(owner.id, cred.id);
    expect(lastGood).not.toBeNull();
    expect(lastGood?.health).toBe("healthy");
    expect(lastGood?.stale).toBe(false);
    expect(lastGood?.source).toBe("live");
    expect(lastGood?.lastGoodFetchedAt).toBe(t1);
    expect(lastGood?.limits[0]?.amount.remaining).toBe(25.5);

    vault.close();
  });

  it("retains prior limits and sets health=stale, stale=true, source=stale on later network error", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("user2@example.com", "passwordhash");
    const cred = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Production Key",
      credentialType: "api_key",
      secret: "sk-test",
    });

    const registry = new ProviderRegistry();
    const adapter = new DeepSeekAdapter();
    registry.register(adapter);
    const poller = new PollerEngine(vault, registry);

    const t1 = 1700000000000;
    adapter.fetchUsage = async () => ({
      provider: "deepseek",
      fetchedAt: t1,
      limits: [
        {
          id: "balance",
          label: "Balance",
          amount: { remaining: 88.0, unit: "usd" },
          status: "ok",
        },
      ],
    });

    // 1st poll succeeds
    const firstReport = await poller.pollCredential(owner.id, cred.id);
    expect(firstReport?.health).toBe("healthy");
    expect(firstReport?.stale).toBe(false);

    // 2nd poll encounters transport/network failure
    adapter.fetchUsage = async () => {
      throw new Error("Connection reset by peer");
    };

    const secondReport = await poller.pollCredential(owner.id, cred.id);
    expect(secondReport).not.toBeNull();
    expect(secondReport?.health).toBe("stale");
    expect(secondReport?.stale).toBe(true);
    expect(secondReport?.source).toBe("stale");
    expect(secondReport?.error).toBe("Connection reset by peer");
    expect(secondReport?.lastGoodFetchedAt).toBe(t1);
    expect(secondReport?.limits.length).toBe(1);
    expect(secondReport?.limits[0]?.amount.remaining).toBe(88.0);
    expect(secondReport?.provider).toBe("deepseek");
    expect(secondReport?.accountLabel).toBe("Production Key");
    expect(secondReport?.ownerId).toBe(owner.id);
    expect(secondReport?.credentialId).toBe(cred.id);

    // Check that latest snapshot in vault is the stale one with retained limits
    const latest = vault.getLatestUsage(owner.id);
    expect(latest.length).toBe(1);
    expect(latest[0]?.health).toBe("stale");
    expect(latest[0]?.stale).toBe(true);
    expect(latest[0]?.source).toBe("stale");
    expect(latest[0]?.limits[0]?.amount.remaining).toBe(88.0);
    expect(latest[0]?.error).toBe("Connection reset by peer");
    expect(latest[0]?.lastGoodFetchedAt).toBe(t1);

    // Check that getLastSuccessfulUsage still correctly returns the t1 success snapshot
    const lastGood = vault.getLastSuccessfulUsage(owner.id, cred.id);
    expect(lastGood).not.toBeNull();
    expect(lastGood?.health).toBe("healthy");
    expect(lastGood?.stale).toBe(false);
    expect(lastGood?.fetchedAt).toBe(t1);

    vault.close();
  });

  it("produces empty limits, health=error, stale=false, source=error on first-ever failure", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("user3@example.com", "passwordhash");
    const cred = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Broken Key",
      credentialType: "api_key",
      secret: "sk-broken",
    });

    const registry = new ProviderRegistry();
    const adapter = new DeepSeekAdapter();
    registry.register(adapter);
    const poller = new PollerEngine(vault, registry);

    adapter.fetchUsage = async () => {
      throw new Error("401 Invalid API Key");
    };

    const report = await poller.pollCredential(owner.id, cred.id);
    expect(report).not.toBeNull();
    expect(report?.health).toBe("error");
    expect(report?.stale).toBe(false);
    expect(report?.source).toBe("error");
    expect(report?.error).toBe("401 Invalid API Key");
    expect(report?.limits).toEqual([]);
    expect(report?.lastGoodFetchedAt).toBeUndefined();

    // In vault
    const lastGood = vault.getLastSuccessfulUsage(owner.id, cred.id);
    expect(lastGood).toBeNull();

    const latest = vault.getLatestUsage(owner.id);
    expect(latest.length).toBe(1);
    expect(latest[0]?.health).toBe("error");
    expect(latest[0]?.limits).toEqual([]);

    vault.close();
  });

  it("keeps real provider exhausted reports healthy and live, not stale", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("user4@example.com", "passwordhash");
    const cred = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Exhausted Plan",
      credentialType: "api_key",
      secret: "sk-test",
    });

    const registry = new ProviderRegistry();
    const adapter = new DeepSeekAdapter();
    registry.register(adapter);
    const poller = new PollerEngine(vault, registry);

    const t1 = 1700000000000;
    adapter.fetchUsage = async () => ({
      provider: "deepseek",
      fetchedAt: t1,
      limits: [
        {
          id: "monthly",
          label: "Monthly Quota",
          amount: { usedFraction: 1.0, remaining: 0, unit: "tokens" },
          status: "exhausted",
        },
      ],
    });

    const report = await poller.pollCredential(owner.id, cred.id);
    expect(report).not.toBeNull();
    // Must be healthy and live, NOT stale
    expect(report?.health).toBe("healthy");
    expect(report?.stale).toBe(false);
    expect(report?.source).toBe("live");
    expect(report?.lastGoodFetchedAt).toBe(t1);
    expect(report?.limits[0]?.status).toBe("exhausted");

    // The exhausted report is a valid successful report and is preserved by getLastSuccessfulUsage
    const lastGood = vault.getLastSuccessfulUsage(owner.id, cred.id);
    expect(lastGood).not.toBeNull();
    expect(lastGood?.health).toBe("healthy");
    expect(lastGood?.limits[0]?.status).toBe("exhausted");

    vault.close();
  });

  it("enforces tenant isolation on last-good lookups", async () => {
    const vault = new StorageVault(":memory:");
    const userA = vault.createUser("usera@example.com", "hashA");
    const userB = vault.createUser("userb@example.com", "hashB");

    const credA = vault.saveCredential(userA.id, {
      provider: "deepseek",
      accountLabel: "User A Key",
      credentialType: "api_key",
      secret: "sk-a",
    });

    const t1 = 1700000000000;
    const reportA: UsageReport = {
      ownerId: userA.id,
      provider: "deepseek",
      credentialId: credA.id,
      accountLabel: "User A Key",
      fetchedAt: t1,
      health: "healthy",
      stale: false,
      source: "live",
      lastGoodFetchedAt: t1,
      limits: [{ id: "l1", label: "Limit 1", amount: { remaining: 100, unit: "usd" }, status: "ok" }],
    };
    vault.saveUsageSnapshot(userA.id, reportA);

    // User A can retrieve it
    expect(vault.getLastSuccessfulUsage(userA.id, credA.id)).not.toBeNull();

    // User B CANNOT retrieve User A's last successful usage
    expect(vault.getLastSuccessfulUsage(userB.id, credA.id)).toBeNull();

    // Internal daemon lookup succeeds with credentialId
    expect(vault.getLastSuccessfulUsageInternal(credA.id)).not.toBeNull();

    vault.close();
  });

  it("handles legacy snapshots without new fields as fresh compatibility", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("user5@example.com", "hash5");
    const cred = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Legacy Key",
      credentialType: "api_key",
      secret: "sk-legacy",
    });

    const legacyReport: UsageReport = {
      ownerId: owner.id,
      provider: "deepseek",
      credentialId: cred.id,
      accountLabel: "Legacy Key",
      fetchedAt: 1690000000000,
      limits: [{ id: "balance", label: "Balance", amount: { remaining: 42, unit: "usd" }, status: "ok" }],
    };
    // Saving legacyReport without health/stale/source
    vault.saveUsageSnapshot(owner.id, legacyReport);

    // getLastSuccessfulUsage recognizes legacy snapshot without error as successful
    const lastGood = vault.getLastSuccessfulUsage(owner.id, cred.id);
    expect(lastGood).not.toBeNull();
    expect(lastGood?.health).toBe("healthy");
    expect(lastGood?.stale).toBe(false);
    expect(lastGood?.source).toBe("live");
    expect(lastGood?.lastGoodFetchedAt).toBe(1690000000000);
    expect(lastGood?.limits[0]?.amount.remaining).toBe(42);

    // Now test poller: if a subsequent poll fails, it uses the legacy report as last-good
    const registry = new ProviderRegistry();
    const adapter = new DeepSeekAdapter();
    registry.register(adapter);
    const poller = new PollerEngine(vault, registry);

    adapter.fetchUsage = async () => {
      throw new Error("Upstream gateway error");
    };

    const failReport = await poller.pollCredential(owner.id, cred.id);
    expect(failReport?.health).toBe("stale");
    expect(failReport?.stale).toBe(true);
    expect(failReport?.source).toBe("stale");
    expect(failReport?.lastGoodFetchedAt).toBe(1690000000000);
    expect(failReport?.limits[0]?.amount.remaining).toBe(42);
    expect(failReport?.error).toBe("Upstream gateway error");

    vault.close();
  });

  it("preserves new fields in JSON persistence round-trip", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("user6@example.com", "hash6");
    const cred = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Roundtrip Key",
      credentialType: "api_key",
      secret: "sk-rt",
    });

    const report: UsageReport = {
      ownerId: owner.id,
      provider: "deepseek",
      credentialId: cred.id,
      accountLabel: "Roundtrip Key",
      fetchedAt: 1700000050000,
      limits: [{ id: "b", label: "Bal", amount: { remaining: 10, unit: "usd" }, status: "ok" }],
      error: "Temporary glitch",
      health: "stale",
      stale: true,
      lastGoodFetchedAt: 1700000000000,
      source: "stale",
    };

    vault.saveUsageSnapshot(owner.id, report);

    const latest = vault.getLatestUsage(owner.id);
    expect(latest.length).toBe(1);
    expect(latest[0]?.health).toBe("stale");
    expect(latest[0]?.stale).toBe(true);
    expect(latest[0]?.source).toBe("stale");
    expect(latest[0]?.lastGoodFetchedAt).toBe(1700000000000);
    expect(latest[0]?.error).toBe("Temporary glitch");

    // Daemon internal save
    const reportDaemon: UsageReport = {
      ownerId: owner.id,
      provider: "deepseek",
      credentialId: cred.id,
      accountLabel: "Roundtrip Key",
      fetchedAt: 1700000060000,
      limits: [{ id: "b", label: "Bal", amount: { remaining: 10, unit: "usd" }, status: "ok" }],
      health: "healthy",
      stale: false,
      lastGoodFetchedAt: 1700000060000,
      source: "live",
    };
    vault.saveUsageSnapshotInternal(reportDaemon);

    const latestInternal = vault.getLatestUsageInternal();
    const match = latestInternal.find(r => r.credentialId === cred.id);
    expect(match).toBeDefined();
    expect(match?.health).toBe("healthy");
    expect(match?.stale).toBe(false);
    expect(match?.source).toBe("live");
    expect(match?.lastGoodFetchedAt).toBe(1700000060000);

    vault.close();
  });
});

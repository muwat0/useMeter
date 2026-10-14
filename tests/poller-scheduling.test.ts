import { describe, expect, it } from "bun:test";
import { PollerEngine } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import { StorageVault } from "../src/core/storage/vault";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import type { StoredCredential, UsageReport } from "../src/types";

function healthyReport(credential: StoredCredential): UsageReport {
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
}

function fakeAdapter(fetch: ProviderAdapter["fetchUsage"]): ProviderAdapter {
  return {
    id: "poller-scheduling-test",
    supports: provider => provider === "deepseek",
    fetchUsage: fetch,
  };
}

describe("PollerEngine global sweep scheduling", () => {
  it("coalesces concurrent global sweeps across different owners", async () => {
    const vault = new StorageVault(":memory:");
    const firstOwner = vault.createUser("sweep-first@example.com", "hash");
    const secondOwner = vault.createUser("sweep-second@example.com", "hash");
    const first = vault.saveCredential(firstOwner.id, {
      provider: "deepseek",
      accountLabel: "First owner",
      credentialType: "api_key",
      secret: "first-secret",
    });
    const second = vault.saveCredential(secondOwner.id, {
      provider: "deepseek",
      accountLabel: "Second owner",
      credentialType: "api_key",
      secret: "second-secret",
    });
    const firstFetchStarted = Promise.withResolvers<void>();
    const releaseFirstFetch = Promise.withResolvers<void>();
    const calls: string[] = [];
    const registry = new ProviderRegistry();
    registry.register(fakeAdapter(async credential => {
      calls.push(credential.id);
      if (calls.length === 1) {
        firstFetchStarted.resolve();
        await releaseFirstFetch.promise;
      }
      return healthyReport(credential);
    }));
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    let firstSweep: Promise<UsageReport[]> | undefined;

    try {
      firstSweep = poller.pollAll();
      await firstFetchStarted.promise;
      const joinedSweep = poller.pollAll();
      releaseFirstFetch.resolve();
      const [reports, joinedReports] = await Promise.all([firstSweep, joinedSweep]);
      expect([...calls].sort()).toEqual([first.id, second.id].sort());
      expect(reports.map(report => report.ownerId).sort()).toEqual([firstOwner.id, secondOwner.id].sort());
      expect(joinedReports.map(report => report.ownerId).sort()).toEqual([firstOwner.id, secondOwner.id].sort());
      expect(reports.every(report => report.health === "healthy" && !report.error)).toBe(true);
      expect(joinedReports.every(report => report.health === "healthy" && !report.error)).toBe(true);
    } finally {
      releaseFirstFetch.resolve();
      if (firstSweep) await firstSweep;
      poller.stop();
      vault.close();
    }
  });

  it("coalesces timer-triggered sweeps and keeps mid-sweep credentials for the next pass", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("sweep-timer@example.com", "hash");
    const first = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Timer blocker",
      credentialType: "api_key",
      secret: "first-secret",
    });
    const second = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Second credential",
      credentialType: "api_key",
      secret: "second-secret",
    });
    const firstFetchStarted = Promise.withResolvers<void>();
    const releaseFirstFetch = Promise.withResolvers<void>();
    const timerPollAll = Promise.withResolvers<void>();
    const initialSweep = Promise.withResolvers<{ sweep: Promise<UsageReport[]> }>();
    const calls: string[] = [];
    const registry = new ProviderRegistry();
    registry.register(fakeAdapter(async credential => {
      calls.push(credential.id);
      if (credential.id === first.id) {
        firstFetchStarted.resolve();
        await releaseFirstFetch.promise;
      }
      return healthyReport(credential);
    }));
    const poller = new PollerEngine(vault, registry, {
      intervalMs: 250,
      minProviderIntervalMs: 0,
    });
    const originalPollAll = poller.pollAll;
    let pollAllCalls = 0;
    poller.pollAll = () => {
      pollAllCalls++;
      const sweep = originalPollAll.call(poller);
      if (pollAllCalls === 1) initialSweep.resolve({ sweep });
      else timerPollAll.resolve();
      return sweep;
    };
    // A real interval tick is the observable barrier for overlapping sweep coalescing.
    const timerGuard = setTimeout(
      () => timerPollAll.reject(new Error("The poller interval did not trigger a sweep")),
      2_000,
    );
    let sweep: Promise<UsageReport[]> | undefined;

    try {
      poller.start();
      sweep = (await initialSweep.promise).sweep;
      await firstFetchStarted.promise;
      const addedMidSweep = vault.saveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Added during sweep",
        credentialType: "api_key",
        secret: "late-secret",
      });
      await timerPollAll.promise;
      poller.stop();
      releaseFirstFetch.resolve();
      const reports = await sweep;
      expect(calls.sort()).toEqual([first.id, second.id].sort());
      expect(calls).not.toContain(addedMidSweep.id);
      expect(reports.map(report => report.credentialId)).toEqual([first.id, second.id]);
      expect(reports.every(report => report.ownerId === owner.id && report.health === "healthy")).toBe(true);
    } finally {
      clearTimeout(timerGuard);
      poller.pollAll = originalPollAll;
      poller.stop();
      releaseFirstFetch.resolve();
      if (sweep) await sweep;
      vault.close();
    }
  });

  it("releases the global sweep guard after enumeration fails", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("sweep-recovery@example.com", "hash");
    vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Recovery",
      credentialType: "api_key",
      secret: "recovery-secret",
    });
    const registry = new ProviderRegistry();
    registry.register(fakeAdapter(async credential => healthyReport(credential)));
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const listCredentialRefs = vault.listAllCredentialRefsInternal;

    try {
      vault.listAllCredentialRefsInternal = () => {
        throw new Error("injected enumeration failure");
      };
      await expect(poller.pollAll()).rejects.toThrow("injected enumeration failure");
      vault.listAllCredentialRefsInternal = listCredentialRefs;
      const reports = await poller.pollAll();
      expect(reports).toHaveLength(1);
      expect(reports[0]).toMatchObject({ ownerId: owner.id, health: "healthy", source: "live" });
    } finally {
      vault.listAllCredentialRefsInternal = listCredentialRefs;
      poller.stop();
      vault.close();
    }
  });
});

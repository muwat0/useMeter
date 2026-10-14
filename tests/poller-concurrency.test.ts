import { performance } from "node:perf_hooks";
import { describe, expect, it } from "bun:test";
import { PollerAdmissionError, PollerEngine } from "../src/core/poller/poller";
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

function registerProvider(
  registry: ProviderRegistry,
  id: string,
  provider: string,
  fetchUsage: ProviderAdapter["fetchUsage"],
): void {
  registry.register({ id, supports: candidate => candidate === provider, fetchUsage });
}

function createCredentials(vault: StorageVault, ownerId: string, provider: string, count: number): void {
  for (let index = 0; index < count; index++) {
    vault.saveCredential(ownerId, {
      provider,
      accountLabel: `${provider} account ${index}`,
      credentialType: "api_key",
      secret: `${provider}-secret-${index}`,
    });
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs = 2_000): Promise<T> {
  const { promise: timeout, reject } = Promise.withResolvers<never>();
  // This is only a deadlock guard; successful tests await explicit scheduler events.
  const timer = setTimeout(() => reject(new Error(`Timed out after ${timeoutMs} ms`)), timeoutMs);
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function waitFor(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
}

describe("PollerEngine bounded provider polling", () => {
  it("pollUser returns reports across provider groups", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-user-refs@example.com", "hash");
    const providers = ["provider-a", "provider-b", "provider-c"];
    for (const provider of providers) createCredentials(vault, owner.id, provider, 1);
    const atGlobalCap = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let active = 0;
    for (const provider of providers) {
      registerProvider(registry, provider, provider, async credential => {
        active++;
        if (active === 2) atGlobalCap.resolve();
        await release.promise;
        active--;
        return healthyReport(credential);
      });
    }
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 2,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
    });
    let polling: Promise<UsageReport[]> | undefined;

    try {
      polling = poller.pollUser(owner.id);
      await withTimeout(atGlobalCap.promise);
      release.resolve();
      const reports = await withTimeout(polling);
      expect(reports).toHaveLength(3);
      expect(reports.every(report => report.ownerId === owner.id && report.health === "healthy")).toBe(true);
    } finally {
      release.resolve();
      if (polling) await polling.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("keeps a global concurrency cap across 20 credentials", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-global-cap@example.com", "hash");
    const providers = ["provider-a", "provider-b", "provider-c", "provider-d", "provider-e"];
    for (const provider of providers) createCredentials(vault, owner.id, provider, 4);
    const atCap = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let active = 0;
    let maximumActive = 0;
    const fetchUsage: ProviderAdapter["fetchUsage"] = async credential => {
      active++;
      maximumActive = Math.max(maximumActive, active);
      if (active === 4) atCap.resolve();
      await release.promise;
      active--;
      return healthyReport(credential);
    };
    for (const provider of providers) registerProvider(registry, provider, provider, fetchUsage);

    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 4,
      maxConcurrentPerProvider: 2,
      minProviderIntervalMs: 0,
    });
    let sweep: Promise<UsageReport[]> | undefined;

    try {
      sweep = poller.pollAll();
      await withTimeout(atCap.promise);
      release.resolve();
      const reports = await withTimeout(sweep);
      expect(reports).toHaveLength(20);
      expect(reports.every(report => report.health === "healthy")).toBe(true);
      expect(maximumActive).toBe(4);
    } finally {
      release.resolve();
      if (sweep) await sweep.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("caps one canonical provider at two while another proceeds", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-provider-cap@example.com", "hash");
    createCredentials(vault, owner.id, "anthropic", 2);
    createCredentials(vault, owner.id, "anthropic-alias", 2);
    createCredentials(vault, owner.id, "deepseek", 1);

    const anthropicAtCap = Promise.withResolvers<void>();
    const deepseekStarted = Promise.withResolvers<void>();
    const releaseAnthropic = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let activeAnthropic = 0;
    let maximumAnthropic = 0;
    registry.register({
      id: "anthropic",
      supports: provider => provider === "anthropic" || provider === "anthropic-alias",
      fetchUsage: async credential => {
        activeAnthropic++;
        maximumAnthropic = Math.max(maximumAnthropic, activeAnthropic);
        if (activeAnthropic === 2) anthropicAtCap.resolve();
        await releaseAnthropic.promise;
        activeAnthropic--;
        return healthyReport(credential);
      },
    });
    registerProvider(registry, "deepseek-adapter", "deepseek", async credential => {
      deepseekStarted.resolve();
      return healthyReport(credential);
    });

    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 3,
      maxConcurrentPerProvider: 2,
      minProviderIntervalMs: 0,
    });
    const credentials = vault.listCredentials(owner.id);
    const polls: Promise<UsageReport | null>[] = [];

    try {
      for (const credential of credentials) {
        polls.push(poller.pollCredential(owner.id, credential.id));
      }
      await withTimeout(Promise.all([anthropicAtCap.promise, deepseekStarted.promise]));
      expect(maximumAnthropic).toBe(2);
      releaseAnthropic.resolve();
      const reports = await withTimeout(Promise.all(polls));
      expect(reports).toHaveLength(5);
      expect(maximumAnthropic).toBe(2);
    } finally {
      releaseAnthropic.resolve();
      await Promise.all(polls).catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("does not let a provider cooldown waiter starve a ready provider", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-ready-provider@example.com", "hash");
    const first = vault.saveCredential(owner.id, {
      provider: "provider-a",
      accountLabel: "a-first",
      credentialType: "api_key",
      secret: "a-first-secret",
    });
    const second = vault.saveCredential(owner.id, {
      provider: "provider-a",
      accountLabel: "a-second",
      credentialType: "api_key",
      secret: "a-second-secret",
    });
    const ready = vault.saveCredential(owner.id, {
      provider: "provider-b",
      accountLabel: "b-ready",
      credentialType: "api_key",
      secret: "b-secret",
    });
    const firstStarted = Promise.withResolvers<void>();
    const readyStarted = Promise.withResolvers<void>();
    const secondStarted = Promise.withResolvers<void>();
    const releaseFirst = Promise.withResolvers<void>();
    const calls: string[] = [];
    const registry = new ProviderRegistry();
    registry.register({
      id: "provider-a",
      supports: provider => provider === "provider-a",
      fetchUsage: async credential => {
        calls.push(credential.accountLabel);
        if (credential.id === first.id) {
          firstStarted.resolve();
          await releaseFirst.promise;
        }
        if (credential.id === second.id) secondStarted.resolve();
        return healthyReport(credential);
      },
    });
    registerProvider(registry, "provider-b", "provider-b", async credential => {
      calls.push(credential.accountLabel);
      readyStarted.resolve();
      return healthyReport(credential);
    });
    // Real monotonic time exercises cooldown eligibility without holding a global slot.
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 250,
      admissionTimeoutMs: 2_000,
    });
    let firstPoll: Promise<UsageReport | null> | undefined;
    let secondPoll: Promise<UsageReport | null> | undefined;
    let readyPoll: Promise<UsageReport | null> | undefined;

    try {
      firstPoll = poller.pollCredential(owner.id, first.id);
      await withTimeout(firstStarted.promise);
      secondPoll = poller.pollCredential(owner.id, second.id);
      readyPoll = poller.pollCredential(owner.id, ready.id);
      releaseFirst.resolve();
      await withTimeout(readyStarted.promise);
      expect(calls).toEqual(["a-first", "b-ready"]);
      await withTimeout(Promise.all([firstPoll, secondPoll, readyPoll]));
      await withTimeout(secondStarted.promise);
      expect(calls).toEqual(["a-first", "b-ready", "a-second"]);
    } finally {
      releaseFirst.resolve();
      await Promise.all([firstPoll, secondPoll, readyPoll].filter(Boolean)).catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("single-flights duplicate credential polls while queued and active", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-single-flight@example.com", "hash");
    const blocker = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Blocker",
      credentialType: "api_key",
      secret: "blocker-secret",
    });
    const target = vault.saveCredential(owner.id, {
      provider: "openrouter",
      accountLabel: "Shared target",
      credentialType: "api_key",
      secret: "target-secret",
    });
    const blockerStarted = Promise.withResolvers<void>();
    const releaseBlocker = Promise.withResolvers<void>();
    const targetStarted = Promise.withResolvers<void>();
    const releaseTarget = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let targetFetches = 0;
    registry.register({
      id: "single-flight-adapter",
      supports: provider => provider === "deepseek" || provider === "openrouter",
      fetchUsage: async credential => {
        if (credential.id === blocker.id) {
          blockerStarted.resolve();
          await releaseBlocker.promise;
        }
        if (credential.id === target.id) {
          targetFetches++;
          targetStarted.resolve();
          await releaseTarget.promise;
        }
        return healthyReport(credential);
      },
    });
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
      maxQueuedJobs: 1,
    });
    let blockerPoll: Promise<UsageReport | null> | undefined;
    let firstTargetPoll: Promise<UsageReport | null> | undefined;
    let duplicateQueuedPoll: Promise<UsageReport | null> | undefined;
    let duplicateActivePoll: Promise<UsageReport | null> | undefined;

    try {
      blockerPoll = poller.pollCredential(owner.id, blocker.id);
      await withTimeout(blockerStarted.promise);
      firstTargetPoll = poller.pollCredential(owner.id, target.id);
      duplicateQueuedPoll = poller.pollCredential(owner.id, target.id);
      releaseBlocker.resolve();
      await withTimeout(targetStarted.promise);
      duplicateActivePoll = poller.pollCredential(owner.id, target.id);
      releaseTarget.resolve();
      const reports = await withTimeout(Promise.all([
        blockerPoll,
        firstTargetPoll,
        duplicateQueuedPoll,
        duplicateActivePoll,
      ]));
      expect(targetFetches).toBe(1);
      expect(reports.slice(1).map(report => report?.credentialId)).toEqual([
        target.id,
        target.id,
        target.id,
      ]);
    } finally {
      releaseBlocker.resolve();
      releaseTarget.resolve();
      await Promise.all([
        blockerPoll,
        firstTargetPoll,
        duplicateQueuedPoll,
        duplicateActivePoll,
      ].filter(Boolean)).catch(() => {});
      poller.stop();
      vault.close();
    }
  });
  it("does not let a queued unowned daemon reference shadow an owner's claimed legacy credential", async () => {
    const vault = new StorageVault(":memory:");
    vault.saveCredentialInternal({
      provider: "deepseek",
      accountLabel: "Legacy blocker",
      credentialType: "api_key",
      secret: "blocker-secret",
    });
    const target = vault.saveCredentialInternal({
      provider: "openrouter",
      accountLabel: "Legacy target",
      credentialType: "oauth",
      secret: "legacy-target-secret",
    });
    const blockerStarted = Promise.withResolvers<void>();
    const releaseBlocker = Promise.withResolvers<void>();
    const targetOwners: string[] = [];
    let targetCalls = 0;
    const registry = new ProviderRegistry();
    registry.register({
      id: "legacy-blocker-adapter",
      supports: provider => provider === "deepseek",
      fetchUsage: async credential => {
        blockerStarted.resolve();
        await releaseBlocker.promise;
        return healthyReport(credential);
      },
    });
    registry.register({
      id: "legacy-target-adapter",
      supports: provider => provider === "openrouter",
      fetchUsage: async credential => {
        targetCalls++;
        targetOwners.push(credential.ownerId ?? "");
        return {
          ...healthyReport(credential),
          limits: [{
            id: "quota",
            label: "Requests",
            amount: { remaining: 7, unit: "requests" },
            status: "ok",
          }],
        };
      },
    });
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
    });
    let sweep: Promise<UsageReport[]> | undefined;
    let ownerPoll: Promise<UsageReport | null> | undefined;

    try {
      sweep = poller.pollAll();
      await withTimeout(blockerStarted.promise);
      const { user: owner, claimedLegacy } = vault.createUserWithLegacyClaim(
        "legacy-claim@example.com",
        "hash",
      );
      expect(claimedLegacy).toBe(true);
      expect(vault.getCredentialRefInternal(target.id)?.ownerId).toBe(owner.id);
      expect(vault.getCredentialRef("foreign-owner", target.id)).toBeNull();
      expect(await poller.pollCredential("foreign-owner", target.id)).toBeNull();
      expect(targetCalls).toBe(0);

      ownerPoll = poller.pollCredential(owner.id, target.id);
      releaseBlocker.resolve();
      const [sweepReports, ownerReport] = await withTimeout(
        Promise.all([sweep, ownerPoll]),
      );
      expect(sweepReports).toEqual([]);
      expect(ownerReport).toMatchObject({
        ownerId: owner.id,
        credentialId: target.id,
        health: "healthy",
        limits: [{ amount: { remaining: 7 } }],
      });
      expect(targetCalls).toBe(1);
      expect(targetOwners).toEqual([owner.id]);
    } finally {
      releaseBlocker.resolve();
      if (sweep) await sweep.catch(() => {});
      if (ownerPoll) await ownerPoll.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("cancels staged validation promptly while it waits for a provider cooldown", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-cancel-cooldown@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "anthropic",
      accountLabel: "Existing",
      credentialType: "api_key",
      secret: "existing-secret",
    });
    const requestStarted = Promise.withResolvers<void>();
    const releaseRequest = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let requests = 0;
    registerProvider(registry, "anthropic-adapter", "anthropic", async current => {
      requests++;
      if (current.id === credential.id) {
        requestStarted.resolve();
        await releaseRequest.promise;
      }
      return healthyReport(current);
    });
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 2,
      maxConcurrentPerProvider: 2,
      minProviderIntervalMs: 250,
      admissionTimeoutMs: 2_000,
    });
    let poll: Promise<UsageReport | null> | undefined;

    try {
      poll = poller.pollCredential(owner.id, credential.id);
      await withTimeout(requestStarted.promise);
      const controller = new AbortController();
      const validation = poller.validateAndSaveCredential(owner.id, {
        provider: "anthropic",
        accountLabel: "Canceled candidate",
        credentialType: "api_key",
        secret: "candidate-secret",
      }, "replace", { signal: controller.signal });
      controller.abort(new Error("cooldown validation canceled"));
      await expect(validation).rejects.toThrow("cooldown validation canceled");
      releaseRequest.resolve();
      await withTimeout(poll);
      expect(requests).toBe(1);
      expect(vault.listCredentials(owner.id)).toHaveLength(1);
    } finally {
      releaseRequest.resolve();
      if (poll) await poll.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("bounds pending admissions and rejects queue-full or expired validation without provider errors", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-admission-bound@example.com", "hash");
    const blocker = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Blocker",
      credentialType: "api_key",
      secret: "blocker-secret",
    });
    const requestStarted = Promise.withResolvers<void>();
    const releaseRequest = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let providerCalls = 0;
    registerProvider(registry, "admission-test", "deepseek", async credential => {
      providerCalls++;
      if (credential.id === blocker.id) {
        requestStarted.resolve();
        await releaseRequest.promise;
      }
      return healthyReport(credential);
    });
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
      maxQueuedJobs: 1,
      admissionTimeoutMs: 40,
      pollTimeoutMs: 1_000,
    });
    let blockerPoll: Promise<UsageReport | null> | undefined;

    try {
      blockerPoll = poller.pollCredential(owner.id, blocker.id);
      await withTimeout(requestStarted.promise);
      const queuedValidation = poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Queued candidate",
        credentialType: "api_key",
        secret: "queued-secret",
      }, "replace");
      const fullQueueValidation = poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Over-capacity candidate",
        credentialType: "api_key",
        secret: "over-capacity-secret",
      }, "replace");

      const queueFullError = await fullQueueValidation.catch(error => error);
      expect(queueFullError).toBeInstanceOf(PollerAdmissionError);
      expect(queueFullError).toMatchObject({ code: "QUEUE_FULL" });
      // The real admission timer is intentionally exercised independently of the provider deadline.
      const timeoutError = await queuedValidation.catch(error => error);
      expect(timeoutError).toBeInstanceOf(PollerAdmissionError);
      expect(timeoutError).toMatchObject({ code: "ADMISSION_TIMEOUT" });
      releaseRequest.resolve();
      await withTimeout(blockerPoll);
      expect(providerCalls).toBe(1);
      expect(vault.listCredentials(owner.id)).toHaveLength(1);
      expect(vault.getLatestUsage(owner.id)).toHaveLength(1);
    } finally {
      releaseRequest.resolve();
      if (blockerPoll) await blockerPoll.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("spaces provider request starts by the configured minimum interval", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-provider-interval@example.com", "hash");
    createCredentials(vault, owner.id, "anthropic", 3);

    const requestStarts: number[] = [];
    const registry = new ProviderRegistry();
    registerProvider(registry, "anthropic-adapter", "anthropic", async credential => {
      requestStarts.push(performance.now());
      return healthyReport(credential);
    });
    const minimumIntervalMs = 100;
    // Real elapsed time verifies the actual adapter dispatch interval on the monotonic clock.
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 3,
      maxConcurrentPerProvider: 3,
      minProviderIntervalMs: minimumIntervalMs,
      pollTimeoutMs: 50,
    });

    try {
      const credentials = vault.listCredentials(owner.id);
      const reports = await withTimeout(Promise.all(
        credentials.map(credential => poller.pollCredential(owner.id, credential.id)),
      ));
      const starts = requestStarts.sort((left, right) => left - right);
      expect(reports).toHaveLength(3);
      expect(starts).toHaveLength(3);
      expect(starts[1]! - starts[0]!).toBeGreaterThanOrEqual(minimumIntervalMs - 2);
      expect(starts[2]! - starts[1]!).toBeGreaterThanOrEqual(minimumIntervalMs - 2);
    } finally {
      poller.stop();
      vault.close();
    }
  });

  it("shares the canonical provider interval across daemon, manual, and staged validation", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-shared-budget@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "anthropic",
      accountLabel: "Existing account",
      credentialType: "api_key",
      secret: "existing-secret",
    });
    const requestStarts: number[] = [];
    const registry = new ProviderRegistry();
    registry.register({
      id: "anthropic-canonical",
      supports: provider => provider === "anthropic" || provider === "anthropic-alias",
      fetchUsage: async current => {
        requestStarts.push(performance.now());
        return healthyReport(current);
      },
    });
    const minimumIntervalMs = 40;
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 3,
      maxConcurrentPerProvider: 3,
      minProviderIntervalMs: minimumIntervalMs,
    });

    try {
      const daemonReports = await withTimeout(poller.pollAll());
      const manualReport = await withTimeout(poller.pollCredential(owner.id, credential.id));
      const candidate = await withTimeout(poller.validateAndSaveCredential(owner.id, {
        provider: "anthropic-alias",
        accountLabel: "Alias account",
        credentialType: "api_key",
        secret: "alias-secret",
      }, "replace"));
      const starts = requestStarts.sort((left, right) => left - right);
      expect(daemonReports).toHaveLength(1);
      expect(manualReport?.credentialId).toBe(credential.id);
      expect(candidate.provider).toBe("anthropic-alias");
      expect(starts).toHaveLength(3);
      expect(starts[1]! - starts[0]!).toBeGreaterThanOrEqual(minimumIntervalMs - 2);
      expect(starts[2]! - starts[1]!).toBeGreaterThanOrEqual(minimumIntervalMs - 2);
    } finally {
      poller.stop();
      vault.close();
    }
  });

  it("cancels staged validation while it is queued behind an active provider request", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-cancel-queued@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "anthropic",
      accountLabel: "Existing account",
      credentialType: "api_key",
      secret: "existing-secret",
    });
    const requestStarted = Promise.withResolvers<void>();
    const releaseRequest = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let requests = 0;
    registerProvider(registry, "anthropic-adapter", "anthropic", async current => {
      requests++;
      if (current.id === credential.id) {
        requestStarted.resolve();
        await releaseRequest.promise;
      }
      return healthyReport(current);
    });
    const poller = new PollerEngine(vault, registry, {
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
    });
    let poll: Promise<UsageReport | null> | undefined;

    try {
      poll = poller.pollCredential(owner.id, credential.id);
      await withTimeout(requestStarted.promise);
      const controller = new AbortController();
      const validation = poller.validateAndSaveCredential(owner.id, {
        provider: "anthropic",
        accountLabel: "Candidate account",
        credentialType: "api_key",
        secret: "candidate-secret",
      }, "replace", { signal: controller.signal });
      controller.abort(new Error("queued validation canceled"));
      await expect(validation).rejects.toThrow("queued validation canceled");
      releaseRequest.resolve();
      await withTimeout(poll);
      expect(requests).toBe(1);
      expect(vault.listCredentials(owner.id)).toHaveLength(1);
    } finally {
      releaseRequest.resolve();
      if (poll) await poll.catch(() => {});
      poller.stop();
      vault.close();
    }
  });

  it("lets an active sweep finish after stop and prevents later scheduled sweeps", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("poller-stop@example.com", "hash");
    createCredentials(vault, owner.id, "anthropic", 1);

    const requestStarted = Promise.withResolvers<void>();
    const releaseRequest = Promise.withResolvers<void>();
    const registry = new ProviderRegistry();
    let requests = 0;
    registerProvider(registry, "anthropic-adapter", "anthropic", async credential => {
      requests++;
      requestStarted.resolve();
      await releaseRequest.promise;
      return healthyReport(credential);
    });
    const poller = new PollerEngine(vault, registry, {
      intervalMs: 15,
      maxConcurrentGlobal: 1,
      maxConcurrentPerProvider: 1,
      minProviderIntervalMs: 0,
    });
    let sweep: Promise<UsageReport[]> | undefined;

    try {
      poller.start();
      await withTimeout(requestStarted.promise);
      sweep = poller.pollAll();
      poller.stop();
      releaseRequest.resolve();
      const reports = await withTimeout(sweep);
      // Let multiple real interval ticks pass to verify stop cleared the recurring timer.
      await waitFor(40);
      expect(reports).toHaveLength(1);
      expect(requests).toBe(1);
    } finally {
      releaseRequest.resolve();
      poller.stop();
      if (sweep) await sweep.catch(() => {});
      vault.close();
    }
  });
});

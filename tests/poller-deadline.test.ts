import { createServer, type Server } from "node:http";
import { performance } from "node:perf_hooks";
import { describe, expect, it } from "bun:test";
import { PollerEngine } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import { StorageVault } from "../src/core/storage/vault";
import type { FetchContext, ProviderAdapter } from "../src/core/providers/adapter";
import type { StoredCredential, UsageReport } from "../src/types";

function report(credential: StoredCredential, remaining: number): UsageReport {
  return {
    ownerId: credential.ownerId,
    provider: credential.provider,
    credentialId: credential.id,
    accountLabel: credential.accountLabel,
    fetchedAt: Date.now(),
    limits: [{
      id: "balance",
      label: "Balance",
      amount: { remaining, unit: "usd" },
      status: "ok",
    }],
  };
}

function adapter(fetchUsage: ProviderAdapter["fetchUsage"]): ProviderAdapter {
  return {
    id: "poller-deadline-test",
    supports: provider => provider === "deepseek",
    fetchUsage,
  };
}

function listen(server: Server): Promise<string> {
  const { promise, resolve, reject } = Promise.withResolvers<string>();
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") {
      reject(new Error("Loopback fixture did not bind a TCP port"));
      return;
    }
    resolve(`http://127.0.0.1:${address.port}`);
  });
  return promise;
}

function close(server: Server): Promise<void> {
  const { promise, resolve, reject } = Promise.withResolvers<void>();
  server.close(error => {
    if (error) reject(error);
    else resolve();
  });
  return promise;
}

// Real timers are required here: fake time cannot prove the monotonic deadline or abort a native loopback HTTP socket.
describe("PollerEngine provider deadlines", () => {
  it("aborts a held native HTTP request, retains last-good limits, and proceeds to the next credential", async () => {
    const slowStarted = Promise.withResolvers<void>();
    const slowResponseClosed = Promise.withResolvers<void>();
    const fastStarted = Promise.withResolvers<void>();
    const server = createServer((request, response) => {
      if (request.url === "/slow") {
        slowStarted.resolve();
        response.on("close", () => {
          if (!response.writableEnded) slowResponseClosed.resolve();
        });
        return;
      }
      fastStarted.resolve();
      response.writeHead(200, { connection: "close" });
      response.end("ok");
    });
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-wire@example.com", "hash");
    const slowCredential = vault.saveCredential(owner.id, {
      provider: "claude",
      accountLabel: "Held provider",
      credentialType: "api_key",
      secret: "slow",
    });
    const priorFetchedAt = Date.now() - 1_000;
    vault.saveUsageSnapshot(owner.id, {
      ownerId: owner.id,
      provider: slowCredential.provider,
      credentialId: slowCredential.id,
      accountLabel: slowCredential.accountLabel,
      fetchedAt: priorFetchedAt,
      limits: [{
        id: "balance",
        label: "Balance",
        amount: { remaining: 71, unit: "usd" },
        status: "ok",
      }],
      health: "healthy",
      stale: false,
      source: "live",
      lastGoodFetchedAt: priorFetchedAt,
    });
    const fastCredential = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Fast provider",
      credentialType: "api_key",
      secret: "fast",
    });
    const registry = new ProviderRegistry();
    let baseUrl = "";
    registry.register({
      id: "poller-deadline-native-http",
      supports: provider => provider === "claude" || provider === "deepseek",
      fetchUsage: async (credential, context) => {
        const endpoint = credential.secret === "slow" ? "/slow" : "/fast";
        const response = await fetch(`${baseUrl}${endpoint}`, { signal: context?.signal });
        if (!response.ok) throw new Error(`Fixture HTTP ${response.status}`);
        await response.text();
        return report(credential, 23);
      },
    });
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 150 });
    let listening = false;

    try {
      baseUrl = await listen(server);
      listening = true;
      const polling = poller.pollUser(owner.id);
      await slowStarted.promise;
      const reports = await polling;
      await slowResponseClosed.promise;
      await fastStarted.promise;

      const stale = reports.find(item => item.credentialId === slowCredential.id);
      const healthy = reports.find(item => item.credentialId === fastCredential.id);
      expect(stale).toMatchObject({ health: "stale", stale: true, source: "stale" });
      expect(stale?.limits[0]?.amount.remaining).toBe(71);
      expect(stale?.error?.toLowerCase()).toContain("timeout");
      expect(healthy).toMatchObject({ health: "healthy", stale: false, source: "live" });
      expect(healthy?.limits[0]?.amount.remaining).toBe(23);
    } finally {
      poller.stop();
      vault.close();
      if (listening) await close(server);
    }
  });

  it("turns an uncooperative first-ever request into an error and frees its credential slot", async () => {
    const firstStarted = Promise.withResolvers<void>();
    const lateFetch = Promise.withResolvers<UsageReport>();
    const lateFetchSettled = Promise.withResolvers<void>();
    lateFetch.promise.then(() => lateFetchSettled.resolve(), () => lateFetchSettled.resolve());
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-recovery@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Uncooperative provider",
      credentialType: "api_key",
      secret: "initial",
    });
    const registry = new ProviderRegistry();
    let calls = 0;
    let firstSignal: AbortSignal | undefined;
    registry.register(adapter((current, context) => {
      calls++;
      if (calls === 1) {
        firstSignal = context?.signal;
        firstStarted.resolve();
        return lateFetch.promise;
      }
      return Promise.resolve(report(current, 38));
    }));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 50 });

    try {
      const firstPoll = poller.pollCredential(owner.id, credential.id);
      await firstStarted.promise;
      const failed = await firstPoll;
      expect(firstSignal?.aborted).toBe(true);
      expect(failed).toMatchObject({ health: "error", stale: false, source: "error", limits: [] });
      expect(failed?.error?.toLowerCase()).toContain("timeout");

      const recovered = await poller.pollCredential(owner.id, credential.id);
      expect(calls).toBe(2);
      expect(recovered).toMatchObject({ health: "healthy", source: "live" });
      lateFetch.reject(new Error("late provider rejection"));
      await lateFetchSettled.promise;
      expect(vault.getLatestUsage(owner.id)[0]).toMatchObject({ health: "healthy", source: "live" });
    } finally {
      lateFetch.reject(new Error("release uncooperative fixture"));
      poller.stop();
      vault.close();
    }
  });

  it("persists an in-deadline token rotation but rejects a same-epoch late callback and report", async () => {
    const lateFetch = Promise.withResolvers<UsageReport>();
    const lateFetchSettled = Promise.withResolvers<void>();
    lateFetch.promise.then(() => lateFetchSettled.resolve(), () => lateFetchSettled.resolve());
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-refresh@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Rotating provider",
      credentialType: "oauth",
      secret: "old-secret",
    });
    const registry = new ProviderRegistry();
    let calls = 0;
    let lateRefresh: FetchContext["onTokenRefresh"];
    registry.register(adapter((current, context) => {
      calls++;
      if (calls === 1) {
        context?.onTokenRefresh?.("rotated-before-deadline");
        lateRefresh = context?.onTokenRefresh;
        return lateFetch.promise;
      }
      return Promise.resolve(report(current, 36));
    }));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 50 });

    try {
      const failed = await poller.pollCredential(owner.id, credential.id);
      expect(failed).toMatchObject({ health: "error", source: "error" });
      expect(vault.getCredential(owner.id, credential.id)?.secret).toBe("rotated-before-deadline");

      const healthy = await poller.pollCredential(owner.id, credential.id);
      expect(healthy).toMatchObject({ health: "healthy", source: "live" });
      expect(healthy?.limits[0]?.amount.remaining).toBe(36);

      if (typeof lateRefresh !== "function") throw new Error("First provider callback was not captured");
      lateRefresh("late-secret");
      lateFetch.resolve(report(credential, 99));
      await lateFetchSettled.promise;
      expect(vault.getCredential(owner.id, credential.id)?.secret).toBe("rotated-before-deadline");
      expect(vault.getLatestUsage(owner.id)[0]).toMatchObject({ health: "healthy", source: "live" });
      expect(vault.getLatestUsage(owner.id)[0]?.limits[0]?.amount.remaining).toBe(36);
    } finally {
      lateFetch.resolve(report(credential, 99));
      poller.stop();
      vault.close();
    }
  });

  it("times out staged validation without replacing an existing credential or last-good snapshot", async () => {
    const requestStarted = Promise.withResolvers<void>();
    const requestClosed = Promise.withResolvers<void>();
    const server = createServer((request, response) => {
      if (request.url !== "/validation") {
        response.writeHead(404);
        response.end();
        return;
      }
      requestStarted.resolve();
      response.on("close", () => {
        if (!response.writableEnded) requestClosed.resolve();
      });
    });
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("validation-deadline-existing@example.com", "hash");
    const existing = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Existing account",
      accent: "amber",
      credentialType: "oauth",
      secret: "prior-secret",
      metadata: { refreshToken: "prior-refresh", accountId: "prior-account" },
    });
    const priorFetchedAt = Date.now() - 1_000;
    vault.saveUsageSnapshot(owner.id, {
      ...report(existing, 71),
      fetchedAt: priorFetchedAt,
      health: "healthy",
      stale: false,
      source: "live",
      lastGoodFetchedAt: priorFetchedAt,
    });
    const registry = new ProviderRegistry();
    let baseUrl = "";
    registry.register(adapter(async (candidate, context) => {
      context?.onTokenRefresh?.("candidate-rotated-secret", { refreshToken: "candidate-rotated-refresh" });
      const response = await fetch(`${baseUrl}/validation`, { signal: context?.signal });
      return report(candidate, response.status);
    }));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 100 });
    let listening = false;

    try {
      baseUrl = await listen(server);
      listening = true;
      const validation = poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Existing account",
        credentialType: "oauth",
        secret: "submitted-secret",
        metadata: { refreshToken: "submitted-refresh", accountId: "replacement-account" },
      }, "replace");
      await requestStarted.promise;
      await expect(validation).rejects.toThrow("Provider poll timeout after 100 ms");
      await requestClosed.promise;

      expect(vault.getCredential(owner.id, existing.id)).toMatchObject({
        id: existing.id,
        secret: "prior-secret",
        accent: "amber",
        metadata: { refreshToken: "prior-refresh", accountId: "prior-account" },
      });
      expect(vault.getLatestUsage(owner.id)[0]).toMatchObject({
        fetchedAt: priorFetchedAt,
        health: "healthy",
        source: "live",
        limits: [{ amount: { remaining: 71 } }],
      });
      expect(vault.getLastSuccessfulUsage(owner.id, existing.id)).toMatchObject({
        fetchedAt: priorFetchedAt,
        lastGoodFetchedAt: priorFetchedAt,
        limits: [{ amount: { remaining: 71 } }],
      });
    } finally {
      poller.stop();
      vault.close();
      if (listening) await close(server);
    }
  });

  it("does not insert a first credential or report after an uncooperative validation resolves late", async () => {
    const fetchStarted = Promise.withResolvers<void>();
    const lateFetch = Promise.withResolvers<UsageReport>();
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("validation-deadline-first@example.com", "hash");
    const registry = new ProviderRegistry();
    let candidate: StoredCredential | undefined;
    let lateRefresh: FetchContext["onTokenRefresh"];
    registry.register(adapter((current, context) => {
      candidate = current;
      lateRefresh = context?.onTokenRefresh;
      context?.onTokenRefresh?.("candidate-secret", { refreshToken: "candidate-refresh" }, "candidate-label");
      fetchStarted.resolve();
      return lateFetch.promise;
    }));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 40 });

    try {
      const validation = poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "First account",
        credentialType: "oauth",
        secret: "submitted-secret",
      }, "replace");
      await fetchStarted.promise;
      await expect(validation).rejects.toThrow("Provider poll timeout after 40 ms");
      expect(vault.listCredentials(owner.id)).toHaveLength(0);
      expect(vault.getLatestUsage(owner.id)).toHaveLength(0);

      if (typeof lateRefresh !== "function" || !candidate) {
        throw new Error("Validation did not capture its staged callback and candidate");
      }
      lateRefresh("late-secret", { refreshToken: "late-refresh" }, "late-label");
      lateFetch.resolve(report(candidate, 99));
      await lateFetch.promise;
      expect(vault.listCredentials(owner.id)).toHaveLength(0);
      expect(vault.getLatestUsage(owner.id)).toHaveLength(0);
    } finally {
      lateFetch.reject(new Error("release uncooperative validation fixture"));
      poller.stop();
      vault.close();
    }
  });

  it("does not start staged validation when its caller signal is already aborted", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("validation-pre-abort@example.com", "hash");
    const registry = new ProviderRegistry();
    let calls = 0;
    registry.register(adapter(async credential => {
      calls++;
      return report(credential, 9);
    }));
    const poller = new PollerEngine(vault, registry);
    const controller = new AbortController();
    controller.abort(new Error("caller canceled before validation"));

    try {
      await expect(poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Canceled account",
        credentialType: "oauth",
        secret: "submitted-secret",
      }, "replace", { signal: controller.signal })).rejects.toThrow("caller canceled before validation");
      expect(calls).toBe(0);
      expect(vault.listCredentials(owner.id)).toHaveLength(0);
      expect(vault.getLatestUsage(owner.id)).toHaveLength(0);
    } finally {
      poller.stop();
      vault.close();
    }
  });

  it("aborts a held validation request when its caller cancels and does not save it", async () => {
    const requestStarted = Promise.withResolvers<void>();
    const requestClosed = Promise.withResolvers<void>();
    const server = createServer((request, response) => {
      if (request.url !== "/validation") {
        response.writeHead(404);
        response.end();
        return;
      }
      requestStarted.resolve();
      response.on("close", () => {
        if (!response.writableEnded) requestClosed.resolve();
      });
    });
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("validation-cancel-network@example.com", "hash");
    const registry = new ProviderRegistry();
    let baseUrl = "";
    let attemptSignal: AbortSignal | undefined;
    registry.register(adapter(async (candidate, context) => {
      attemptSignal = context?.signal;
      const response = await fetch(`${baseUrl}/validation`, { signal: context?.signal });
      return report(candidate, response.status);
    }));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 1_000 });
    const controller = new AbortController();
    let listening = false;

    try {
      baseUrl = await listen(server);
      listening = true;
      const validation = poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Canceled account",
        credentialType: "oauth",
        secret: "submitted-secret",
      }, "replace", { signal: controller.signal });
      await requestStarted.promise;
      controller.abort(new Error("caller canceled validation"));
      await expect(validation).rejects.toThrow("caller canceled validation");
      await requestClosed.promise;

      expect(attemptSignal?.aborted).toBe(true);
      expect(vault.listCredentials(owner.id)).toHaveLength(0);
      expect(vault.getLatestUsage(owner.id)).toHaveLength(0);
    } finally {
      if (!controller.signal.aborted) controller.abort();
      poller.stop();
      vault.close();
      if (listening) await close(server);
    }
  });

  it("keeps the staged credential unchanged when the store rejects the final commit", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("validation-before-commit@example.com", "hash");
    const existing = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Existing account",
      accent: "cyan",
      credentialType: "oauth",
      secret: "prior-secret",
      metadata: { refreshToken: "prior-refresh" },
    });
    const registry = new ProviderRegistry();
    registry.register(adapter(async candidate => report(candidate, 11)));
    const poller = new PollerEngine(vault, registry);

    try {
      await expect(poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Existing account",
        credentialType: "oauth",
        secret: "submitted-secret",
        metadata: { refreshToken: "submitted-refresh" },
      }, "replace", { beforeCommit: () => false })).rejects.toThrow(
        "Credential validation was canceled or expired",
      );
      expect(vault.getCredential(owner.id, existing.id)).toMatchObject({
        secret: "prior-secret",
        accent: "cyan",
        metadata: { refreshToken: "prior-refresh" },
      });
      expect(vault.getLatestUsage(owner.id)).toHaveLength(0);
    } finally {
      poller.stop();
      vault.close();
    }
  });

  it("returns success when the real snapshot write crosses the attempt deadline", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-commit-write@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "Slow synchronous snapshot",
      credentialType: "api_key",
      secret: "fixture-secret",
    });
    const originalSaveUsageSnapshot = vault.saveUsageSnapshot;
    let snapshotWriteMs = 0;
    vault.saveUsageSnapshot = (ownerId, fetched) => {
      const saved = originalSaveUsageSnapshot.call(vault, ownerId, fetched);
      const startedAt = performance.now();
      // The real SQLite write has committed; block synchronously to cross the active deadline.
      while (performance.now() - startedAt < 150) {}
      snapshotWriteMs = performance.now() - startedAt;
      return saved;
    };
    const registry = new ProviderRegistry();
    registry.register(adapter(async current => report(current, 7)));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 100 });

    try {
      const result = await poller.pollCredential(owner.id, credential.id);
      expect(snapshotWriteMs).toBeGreaterThan(100);
      expect(result).toMatchObject({ health: "healthy", source: "live" });
      expect(vault.getLatestUsage(owner.id)[0]).toMatchObject({
        health: "healthy",
        source: "live",
        limits: [{ amount: { remaining: 7 } }],
      });
    } finally {
      vault.saveUsageSnapshot = originalSaveUsageSnapshot;
      poller.stop();
      vault.close();
    }
  });

  it("returns staged validation success when its credential write crosses the attempt deadline", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-validation-write@example.com", "hash");
    const originalSaveCredential = vault.saveCredential;
    let credentialWriteMs = 0;
    vault.saveCredential = (ownerId, input) => {
      const saved = originalSaveCredential.call(vault, ownerId, input);
      const startedAt = performance.now();
      // The real SQLite credential write has committed; block synchronously past the deadline.
      while (performance.now() - startedAt < 150) {}
      credentialWriteMs = performance.now() - startedAt;
      return saved;
    };
    const registry = new ProviderRegistry();
    registry.register(adapter(async candidate => report(candidate, 19)));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 100 });

    try {
      const saved = await poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Committed account",
        credentialType: "oauth",
        secret: "committed-secret",
        metadata: { refreshToken: "committed-refresh" },
      }, "replace");
      expect(credentialWriteMs).toBeGreaterThan(100);
      expect(saved.secret).toBe("committed-secret");
      expect(vault.getCredential(owner.id, saved.id)).toMatchObject({
        secret: "committed-secret",
        metadata: { refreshToken: "committed-refresh" },
      });
      expect(vault.getLatestUsage(owner.id)[0]).toMatchObject({
        health: "healthy",
        source: "live",
        limits: [{ amount: { remaining: 19 } }],
      });
    } finally {
      vault.saveCredential = originalSaveCredential;
      poller.stop();
      vault.close();
    }
  });

  it("keeps staged validation successful when a report listener aborts after commit", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-commit-abort@example.com", "hash");
    const registry = new ProviderRegistry();
    registry.register(adapter(async current => report(current, 13)));
    const poller = new PollerEngine(vault, registry);
    const controller = new AbortController();
    const unsubscribe = poller.onReport(() => {
      controller.abort(new Error("caller canceled after committed report"));
    });

    try {
      const saved = await poller.validateAndSaveCredential(owner.id, {
        provider: "deepseek",
        accountLabel: "Committed account",
        credentialType: "oauth",
        secret: "committed-secret",
      }, "replace", { signal: controller.signal });
      expect(controller.signal.aborted).toBe(true);
      expect(saved.secret).toBe("committed-secret");
      expect(vault.getCredential(owner.id, saved.id)?.secret).toBe("committed-secret");
      expect(vault.getLatestUsage(owner.id)[0]).toMatchObject({ health: "healthy", source: "live" });
    } finally {
      unsubscribe();
      poller.stop();
      vault.close();
    }
  });

  it("enforces the logical deadline when the event loop delays its timer", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("deadline-event-loop@example.com", "hash");
    const credential = vault.saveCredential(owner.id, {
      provider: "deepseek",
      accountLabel: "CPU-bound provider",
      credentialType: "oauth",
      secret: "unchanged-secret",
    });
    const registry = new ProviderRegistry();
    let signalWasUnabortedAfterBlock = false;
    let signalWasAbortedAfterCallback = false;
    registry.register(adapter((current, context) => {
      const startedAt = performance.now();
      // Keep the event loop busy past the deadline so its timer cannot fire before the commit guard runs.
      while (performance.now() - startedAt < 40) {}
      signalWasUnabortedAfterBlock = context?.signal?.aborted === false;
      context?.onTokenRefresh?.("late-during-event-loop-lag");
      signalWasAbortedAfterCallback = context?.signal?.aborted === true;
      return Promise.resolve(report(current, 17));
    }));
    const poller = new PollerEngine(vault, registry, { pollTimeoutMs: 10 });

    try {
      const result = await poller.pollCredential(owner.id, credential.id);
      expect(signalWasUnabortedAfterBlock).toBe(true);
      expect(signalWasAbortedAfterCallback).toBe(true);
      expect(result).toMatchObject({ health: "error", source: "error", limits: [] });
      expect(result?.error?.toLowerCase()).toContain("timeout");
      expect(vault.getCredential(owner.id, credential.id)?.secret).toBe("unchanged-secret");
      expect(vault.getLastSuccessfulUsage(owner.id, credential.id)).toBeNull();
    } finally {
      poller.stop();
      vault.close();
    }
  });

  it("rejects poll deadlines outside the timer-safe positive integer range", () => {
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    try {
      for (const pollTimeoutMs of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2_147_483_648]) {
        expect(() => new PollerEngine(vault, registry, { pollTimeoutMs })).toThrow(RangeError);
      }
    } finally {
      vault.close();
    }
  });
});

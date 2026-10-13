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

import { describe, expect, it } from "bun:test";
import { OAuthSessionStore, type OAuthSession } from "../src/core/oauth/session-store";
import { PollerEngine } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import { StorageVault } from "../src/core/storage/vault";
import type { StoredCredential, UsageReport } from "../src/types";

const PROVIDER = "synthetic-oauth-commit";
type CommitSessionData = { verifier?: string };

function healthyReport(credential: StoredCredential): UsageReport {
  return {
    ownerId: credential.ownerId,
    provider: credential.provider,
    accountLabel: credential.accountLabel,
    fetchedAt: Date.now(),
    limits: [],
    health: "healthy",
    stale: false,
    source: "live",
  };
}

function createAdapter(
  fetchUsage: ProviderAdapter["fetchUsage"] = async credential => healthyReport(credential),
): ProviderAdapter {
  return {
    id: PROVIDER,
    supports: provider => provider === PROVIDER,
    fetchUsage,
  };
}

function createClaimedSession(
  store: OAuthSessionStore<CommitSessionData>,
  ownerId: string,
): OAuthSession<CommitSessionData> {
  const session = store.reserve(ownerId, PROVIDER, {});
  if (!store.activate(session, "synthetic-oauth-session", { verifier: "synthetic-verifier" })) {
    throw new Error("Synthetic OAuth session activation failed");
  }
  if (!store.claim(session)) throw new Error("Synthetic OAuth session claim failed");
  return session;
}

describe("OAuth credential commit boundary", () => {
  it("completes an admitted credential after the real SQLite commit crosses the OAuth deadline", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("oauth-commit-boundary@example.test", "synthetic-password-hash");
    let now = 10_000;
    const store = new OAuthSessionStore<CommitSessionData>({
      now: () => now,
      pendingTtlMs: 100,
      terminalTtlMs: 60_000,
      onEnd: session => { session.data.verifier = undefined; },
    });
    const session = createClaimedSession(store, owner.id);
    const registry = new ProviderRegistry();
    registry.register(createAdapter());
    const poller = new PollerEngine(vault, registry);
    const originalSaveCredential = vault.saveCredential;
    let realCredentialWriteCompleted = false;

    vault.saveCredential = (ownerId, input) => {
      const saved = originalSaveCredential.call(vault, ownerId, input);
      realCredentialWriteCompleted = true;
      now = session.expiresAt;
      return saved;
    };

    try {
      const saved = await poller.validateAndSaveCredential(owner.id, {
        ownerId: owner.id,
        provider: PROVIDER,
        accountLabel: "Synthetic provider account",
        credentialType: "oauth",
        secret: "synthetic-access-token",
        metadata: { refreshToken: "synthetic-refresh-token" },
      }, "replace", {
        signal: session.signal,
        beforeCommit: () => store.admitCommit(session),
      });

      expect(realCredentialWriteCompleted).toBe(true);
      expect(now).toBe(session.expiresAt);
      expect(vault.getCredential(owner.id, saved.id)).toMatchObject({
        ownerId: owner.id,
        provider: PROVIDER,
        accountLabel: "Synthetic provider account",
        secret: "synthetic-access-token",
        metadata: { refreshToken: "synthetic-refresh-token" },
      });
      expect(vault.getSnapshotHistory(owner.id, PROVIDER, 24)).toMatchObject([
        { credentialId: saved.id, health: "healthy", source: "live" },
      ]);
      expect(store.complete(session, saved.accountLabel)).toBe(true);
      expect(session.status).toBe("complete");
      expect(session.terminalExpiresAt).toBe(now + 60_000);
      expect(session.data.verifier).toBeUndefined();
    } finally {
      vault.saveCredential = originalSaveCredential;
      poller.stop();
      vault.close();
    }
  });

  it("rejects a session that expires before admission without writing a credential or snapshot", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("oauth-commit-expired@example.test", "synthetic-password-hash");
    let now = 20_000;
    const store = new OAuthSessionStore<CommitSessionData>({
      now: () => now,
      pendingTtlMs: 100,
    });
    const session = createClaimedSession(store, owner.id);
    let admissionCalls = 0;
    const registry = new ProviderRegistry();
    registry.register(createAdapter(async credential => {
      now = session.expiresAt;
      return healthyReport(credential);
    }));
    const poller = new PollerEngine(vault, registry);

    try {
      await expect(poller.validateAndSaveCredential(owner.id, {
        ownerId: owner.id,
        provider: PROVIDER,
        accountLabel: "Expired synthetic account",
        credentialType: "oauth",
        secret: "synthetic-expired-token",
      }, "replace", {
        signal: session.signal,
        beforeCommit: () => {
          admissionCalls++;
          return store.admitCommit(session);
        },
      })).rejects.toThrow();

      expect(admissionCalls).toBe(1);
      expect(session.status).toBe("error");
      expect(session.signal.aborted).toBe(true);
      expect(vault.listCredentials(owner.id, PROVIDER)).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, PROVIDER, 24)).toHaveLength(0);
    } finally {
      poller.stop();
      vault.close();
    }
  });

  it("rejects cancellation during validation before admission without writing a credential or snapshot", async () => {
    const vault = new StorageVault(":memory:");
    const owner = vault.createUser("oauth-commit-canceled@example.test", "synthetic-password-hash");
    const store = new OAuthSessionStore<CommitSessionData>();
    const session = createClaimedSession(store, owner.id);
    let admissionCalls = 0;
    const registry = new ProviderRegistry();
    registry.register(createAdapter(async credential => {
      expect(store.cancel(session.sessionId, owner.id)).toBe(true);
      return healthyReport(credential);
    }));
    const poller = new PollerEngine(vault, registry);

    try {
      await expect(poller.validateAndSaveCredential(owner.id, {
        ownerId: owner.id,
        provider: PROVIDER,
        accountLabel: "Canceled synthetic account",
        credentialType: "oauth",
        secret: "synthetic-canceled-token",
      }, "replace", {
        signal: session.signal,
        beforeCommit: () => {
          admissionCalls++;
          return store.admitCommit(session);
        },
      })).rejects.toThrow();

      expect(admissionCalls).toBe(0);
      expect(session.signal.aborted).toBe(true);
      expect(vault.listCredentials(owner.id, PROVIDER)).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, PROVIDER, 24)).toHaveLength(0);
    } finally {
      poller.stop();
      vault.close();
    }
  });
});

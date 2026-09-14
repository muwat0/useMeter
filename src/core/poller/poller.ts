import type { StorageVault } from "../storage/vault";
import type { ProviderRegistry } from "../providers/registry";
import type { StoredCredential, UsageReport } from "../../types";

export type ReportListener = (report: UsageReport) => void;

export class PollerEngine {
  readonly #vault: StorageVault;
  readonly #registry: ProviderRegistry;
  readonly #intervalMs: number;
  readonly #inFlight: Map<string, Promise<UsageReport | null>> = new Map();
  readonly #listeners: Set<ReportListener> = new Set();
  #timer?: Timer;
  #running = false;

  constructor(vault: StorageVault, registry: ProviderRegistry, intervalMs: number = 5 * 60 * 1000) {
    this.#vault = vault;
    this.#registry = registry;
    this.#intervalMs = intervalMs;
  }

  onReport(listener: ReportListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  start(): void {
    if (this.#running) return;
    this.#running = true;

    // Run initial poll
    this.pollAll().catch(() => {});

    // Schedule periodic polling with jitter
    this.#timer = setInterval(() => {
      this.pollAll().catch(() => {});
    }, this.#intervalMs);
  }

  stop(): void {
    this.#running = false;
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }
  }

  async pollCredential(ownerId: string, credentialId: string): Promise<UsageReport | null> {
    const credential = this.#vault.getCredential(ownerId, credentialId);
    if (!credential || credential.ownerId !== ownerId) return null;
    return this.#pollCredentialInternal(credential, false);
  }

  async pollUser(ownerId: string): Promise<UsageReport[]> {
    const credentials = this.#vault.listCredentials(ownerId);
    const reports: UsageReport[] = [];
    for (const credential of credentials) {
      const report = await this.#pollCredentialInternal(credential, false);
      if (report) reports.push(report);
    }
    return reports;
  }

  async #pollCredentialInternal(cred: StoredCredential, daemon: boolean): Promise<UsageReport | null> {
    const adapter = this.#registry.find(cred.provider);
    if (!adapter) return null;

    const existing = this.#inFlight.get(cred.id);
    if (existing) return existing;

    const promise = (async () => {
      try {
        const ctx = {
          onTokenRefresh: (newSecret: string, metadataUpdates?: Record<string, unknown>, newAccountLabel?: string) => {
            this.#vault.updateCredentialTokens(cred.ownerId!, cred.id, newSecret, metadataUpdates);
            if (newAccountLabel && newAccountLabel !== cred.accountLabel) {
              this.#vault.updateCredentialLabel(cred.ownerId!, cred.id, newAccountLabel);
              cred.accountLabel = newAccountLabel;
            }
          },
        };
        const fetched = await adapter.fetchUsage(cred, ctx);
        if (fetched.error) {
          throw new Error(fetched.error);
        }
        const now = Date.now();
        const fetchedAt = fetched.fetchedAt ?? now;
        const report: UsageReport = {
          ...fetched,
          ownerId: cred.ownerId,
          credentialId: cred.id,
          fetchedAt,
          health: "healthy",
          stale: false,
          source: "live",
          lastGoodFetchedAt: fetchedAt,
        };
        if (daemon) this.#vault.saveUsageSnapshotInternal(report);
        else this.#vault.saveUsageSnapshot(cred.ownerId!, report);

        for (const listener of this.#listeners) {
          try {
            listener(report);
          } catch {}
        }
        return report;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        const lastGood = (cred.ownerId && !daemon)
          ? this.#vault.getLastSuccessfulUsage(cred.ownerId, cred.id)
          : this.#vault.getLastSuccessfulUsageInternal(cred.id);

        const now = Date.now();
        const fallbackReport: UsageReport = lastGood
          ? {
              ownerId: cred.ownerId ?? lastGood.ownerId,
              provider: cred.provider || lastGood.provider,
              credentialId: cred.id,
              accountLabel: cred.accountLabel || lastGood.accountLabel,
              fetchedAt: now,
              limits: lastGood.limits || [],
              error: errorMessage,
              health: "stale",
              stale: true,
              source: "stale",
              lastGoodFetchedAt: lastGood.lastGoodFetchedAt ?? lastGood.fetchedAt,
            }
          : {
              ownerId: cred.ownerId,
              provider: cred.provider,
              credentialId: cred.id,
              accountLabel: cred.accountLabel,
              fetchedAt: now,
              limits: [],
              error: errorMessage,
              health: "error",
              stale: false,
              source: "error",
            };
        if (daemon) this.#vault.saveUsageSnapshotInternal(fallbackReport);
        else this.#vault.saveUsageSnapshot(cred.ownerId!, fallbackReport);
        return fallbackReport;
      } finally {
        this.#inFlight.delete(cred.id);
      }
    })();

    this.#inFlight.set(cred.id, promise);
    return promise;
  }

  async pollAll(): Promise<UsageReport[]> {
    const credentials = this.#vault.listAllCredentialsInternal();
    const reports: UsageReport[] = [];
    for (const cred of credentials) {
      const staggerMs = 400 + Math.floor(Math.random() * 600);
      const { promise, resolve } = Promise.withResolvers<void>();
      setTimeout(resolve, staggerMs);
      await promise;
      const report = await this.#pollCredentialInternal(cred, true);
      if (report) reports.push(report);
    }
    return reports;
  }

  isRunning(): boolean {
    return this.#running;
  }
}

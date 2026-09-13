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

  async pollCredential(cred: StoredCredential): Promise<UsageReport | null> {
    const adapter = this.#registry.find(cred.provider);
    if (!adapter) return null;

    // Single-flight deduplication
    const existing = this.#inFlight.get(cred.id);
    if (existing) return existing;

    const promise = (async () => {
      try {
        const report = await adapter.fetchUsage(cred);
        this.#vault.saveUsageSnapshot(report);

        // Notify listeners (SSE, Alert Engine)
        for (const listener of this.#listeners) {
          try {
            listener(report);
          } catch {}
        }

        return report;
      } catch (error) {
        console.error(`[Poller] ${cred.provider} (${cred.accountLabel}) sorgulama hatası:`, error);
        return null;
      } finally {
        this.#inFlight.delete(cred.id);
      }
    })();

    this.#inFlight.set(cred.id, promise);
    return promise;
  }

  async pollAll(): Promise<UsageReport[]> {
    const credentials = this.#vault.listCredentials();
    const reports: UsageReport[] = [];

    // Jittered stagger: spread executions across 0..5000ms to avoid burst
    for (const cred of credentials) {
      const staggerMs = 400 + Math.floor(Math.random() * 600);
      const { promise, resolve } = Promise.withResolvers<void>();
      setTimeout(resolve, staggerMs);
      await promise;

      const report = await this.pollCredential(cred);
      if (report) reports.push(report);
    }

    return reports;
  }

  isRunning(): boolean {
    return this.#running;
  }
}

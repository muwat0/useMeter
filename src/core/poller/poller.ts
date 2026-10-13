import { performance } from "node:perf_hooks";
import { randomUUID } from "node:crypto";
import type { StorageVault } from "../storage/vault";
import type { ProviderRegistry } from "../providers/registry";
import type { InputCredential, StoredCredential, UsageReport } from "../../types";


function mergeDefinedMetadata(
  base?: Record<string, unknown>,
  updates?: Record<string, unknown> | null,
): Record<string, unknown> | undefined {
  if (!base && !updates) return undefined;
  const merged: Record<string, unknown> = base ? { ...base } : {};
  if (updates && typeof updates === "object") {
    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) {
        merged[key] = value;
      }
    }
  }
  return Object.keys(merged).length > 0 ? merged : undefined;
}
export type ReportListener = (report: UsageReport) => void;

export interface PollerOptions {
  intervalMs?: number;
  pollTimeoutMs?: number;
}

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;
const DEFAULT_POLL_TIMEOUT_MS = 30_000;
const MAX_TIMER_DELAY_MS = 2_147_483_647;


export interface CredentialValidationContext {
  signal?: AbortSignal;
  beforeCommit?: () => boolean;
  accountLabelMode?: "input" | "provider";
}

interface ProviderAttempt {
  signal: AbortSignal;
  isActive(): boolean;
  throwIfInactive(): void;
  commit<T>(operation: () => T): T;
}


export class PollerEngine {
  readonly #vault: StorageVault;
  readonly #registry: ProviderRegistry;
  readonly #intervalMs: number;
  readonly #pollTimeoutMs: number;
  readonly #inFlight: Map<string, Promise<UsageReport | null>> = new Map();
  readonly #credentialEpochs: Map<string, number> = new Map();
  readonly #listeners: Set<ReportListener> = new Set();
  #timer?: Timer;
  #running = false;
  #sweepInFlight?: Promise<UsageReport[]>;
  constructor(vault: StorageVault, registry: ProviderRegistry, options: PollerOptions = {}) {
    const pollTimeoutMs = options.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
    if (
      !Number.isFinite(pollTimeoutMs) ||
      !Number.isInteger(pollTimeoutMs) ||
      pollTimeoutMs < 1 ||
      pollTimeoutMs > MAX_TIMER_DELAY_MS
    ) {
      throw new RangeError(`pollTimeoutMs must be an integer between 1 and ${MAX_TIMER_DELAY_MS}`);
    }
    this.#vault = vault;
    this.#registry = registry;
    this.#intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.#pollTimeoutMs = pollTimeoutMs;
  }
  #getEpoch(credentialId: string): number {
    return this.#credentialEpochs.get(credentialId) ?? 0;
  }

  #bumpEpoch(credentialId: string): number {
    const next = this.#getEpoch(credentialId) + 1;
    this.#credentialEpochs.set(credentialId, next);
    this.#inFlight.delete(credentialId);
    return next;
  }

  async #runWithDeadline<T>(
    externalSignal: AbortSignal | undefined,
    operation: (attempt: ProviderAttempt) => Promise<T> | T,
  ): Promise<T> {
    externalSignal?.throwIfAborted();
    const controller = new AbortController();
    const deadline = performance.now() + this.#pollTimeoutMs;
    let active = true;
    let timedOut = false;
    let inactiveReason: unknown;
    let timeoutError: Error | undefined;
    let timeoutTimer: Timer | undefined;
    let rejectCancellation!: (reason: unknown) => void;
    const cancellation = new Promise<never>((_resolve, reject) => {
      rejectCancellation = reject;
    });
    const getTimeoutError = (): Error => timeoutError ??= new Error(`Provider poll timeout after ${this.#pollTimeoutMs} ms`);
    const deactivate = (reason: unknown, isTimeout: boolean): void => {
      if (!active) return;
      active = false;
      timedOut = isTimeout;
      inactiveReason = reason;
      controller.abort(reason);
      rejectCancellation(reason);
    };
    const isActive = (): boolean => {
      if (!active) return false;
      if (externalSignal?.aborted) {
        deactivate(externalSignal.reason, false);
        return false;
      }
      if (performance.now() >= deadline) {
        deactivate(getTimeoutError(), true);
        return false;
      }
      return true;
    };
    const throwIfInactive = (): void => {
      if (isActive()) return;
      if (timedOut) throw getTimeoutError();
      if (externalSignal?.aborted) externalSignal.throwIfAborted();
      throw inactiveReason;
    };
    const onExternalAbort = (): void => {
      deactivate(externalSignal?.reason, false);
    };
    if (externalSignal) {
      externalSignal.addEventListener("abort", onExternalAbort, { once: true });
      if (externalSignal.aborted) onExternalAbort();
    }
    if (active) {
      timeoutTimer = setTimeout(() => deactivate(getTimeoutError(), true), this.#pollTimeoutMs);
    }

    let committed = false;
    const commit = <T>(operation: () => T): T => {
      throwIfInactive();
      committed = true;
      active = false;
      clearTimeout(timeoutTimer);
      externalSignal?.removeEventListener("abort", onExternalAbort);
      return operation();
    };
    const attempt: ProviderAttempt = {
      signal: controller.signal,
      isActive,
      throwIfInactive,
      commit,
    };
    const work = Promise.resolve().then(() => {
      attempt.throwIfInactive();
      return operation(attempt);
    });

    try {
      const result = await Promise.race([work, cancellation]);
      if (!committed) attempt.throwIfInactive();
      return result;
    } catch (error) {
      if (active && !isActive()) attempt.throwIfInactive();
      throw error;
    } finally {
      active = false;
      clearTimeout(timeoutTimer);
      externalSignal?.removeEventListener("abort", onExternalAbort);
    }
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
    // Schedule periodic polling; per-credential jitter is applied within each sweep.
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

  async validateAndSaveCredential(
    ownerId: string,
    input: InputCredential,
    metadataMode: "replace" | "preserve",
    context: CredentialValidationContext = {},
  ): Promise<StoredCredential> {
    context.signal?.throwIfAborted();
    const adapter = this.#registry.find(input.provider);
    if (!adapter) throw new Error(`No provider adapter for "${input.provider}"`);

    const existingCredentials = this.#vault.listCredentials(ownerId, input.provider);
    const existing = existingCredentials.find(credential => credential.accountLabel === input.accountLabel);
    const now = Date.now();
    const candidateMetadata = mergeDefinedMetadata(undefined, input.metadata);
    const candidate: StoredCredential = {
      id: existing?.id ?? randomUUID(),
      ownerId,
      provider: input.provider.toLowerCase(),
      accountLabel: input.accountLabel,
      accent: input.accent ?? existing?.accent,
      credentialType: input.credentialType,
      secret: input.secret,
      metadata: candidateMetadata,
      createdAt: existing?.createdAt ?? now,
      updatedAt: existing?.updatedAt ?? now,
    };
    const useProviderAccountLabel =
      metadataMode === "preserve" && context.accountLabelMode === "provider";
    let discoveredAccountLabel: string | undefined;

    return this.#runWithDeadline(context.signal, async attempt => {
      const fetched = await adapter.fetchUsage(candidate, {
        signal: attempt.signal,
        onTokenRefresh: (newSecret, metadataUpdates, newAccountLabel) => {
          if (!attempt.isActive()) return;
          candidate.secret = newSecret;
          if (metadataUpdates) {
            candidate.metadata = mergeDefinedMetadata(candidate.metadata, metadataUpdates);
          }
          if (useProviderAccountLabel && newAccountLabel?.trim()) {
            discoveredAccountLabel = newAccountLabel.trim();
            candidate.accountLabel = discoveredAccountLabel;
          }
        },
      });
      context.signal?.throwIfAborted();
      attempt.throwIfInactive();
      if (fetched.error) throw new Error(fetched.error);

      const fetchedAccountLabel = typeof fetched.accountLabel === "string"
        ? fetched.accountLabel.trim()
        : "";
      const accountLabel = useProviderAccountLabel
        ? discoveredAccountLabel ?? (fetchedAccountLabel || candidate.accountLabel)
        : input.accountLabel;
      const existingForAccountLabel = existingCredentials.find(
        credential => credential.accountLabel === accountLabel,
      );
      const currentExisting = existingForAccountLabel
        ? this.#vault.getCredential(ownerId, existingForAccountLabel.id)
        : undefined;
      if (existingForAccountLabel && (
        !currentExisting ||
        currentExisting.ownerId !== ownerId ||
        currentExisting.provider !== input.provider.toLowerCase() ||
        currentExisting.accountLabel !== accountLabel
      )) {
        throw new Error("Credential changed while validation was in progress");
      }
      if (!existingForAccountLabel &&
        this.#vault.listCredentials(ownerId, input.provider).some(credential => credential.accountLabel === accountLabel)
      ) {
        throw new Error("Credential changed while validation was in progress");
      }

      const finalMetadata = metadataMode === "replace"
        ? candidate.metadata
        : mergeDefinedMetadata(currentExisting?.metadata, candidate.metadata);
      if (context.beforeCommit && !context.beforeCommit()) {
        throw new Error("Credential validation was canceled or expired");
      }
      context.signal?.throwIfAborted();
      return attempt.commit(() => {
        const saved = this.#vault.saveCredential(ownerId, {
          ...input,
          ownerId,
          accountLabel,
          accent: input.accent ?? currentExisting?.accent,
          secret: candidate.secret,
          metadata: finalMetadata,
        });
        this.#bumpEpoch(saved.id);
        this.#saveSuccessfulReport(saved, fetched, false);
        return saved;
      });
    });
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

  async #pollCredentialInternal(queuedCredential: StoredCredential, daemon: boolean): Promise<UsageReport | null> {
    const cred = queuedCredential.ownerId
      ? this.#vault.getCredential(queuedCredential.ownerId, queuedCredential.id)
      : this.#vault.getCredentialInternal(queuedCredential.id);
    if (!cred || (queuedCredential.ownerId && cred.ownerId !== queuedCredential.ownerId)) return null;

    const adapter = this.#registry.find(cred.provider);
    if (!adapter) return null;

    const existing = this.#inFlight.get(cred.id);
    if (existing) return existing;
    const epoch = this.#getEpoch(cred.id);

    let promise!: Promise<UsageReport | null>;
    promise = Promise.resolve().then(async () => {
      try {
        return await this.#runWithDeadline(undefined, async attempt => {
          const ctx = {
            signal: attempt.signal,
            onTokenRefresh: (
              newSecret: string,
              metadataUpdates?: Record<string, unknown>,
              newAccountLabel?: string,
            ) => {
              if (this.#getEpoch(cred.id) !== epoch || !attempt.isActive()) {
                return;
              }
              this.#vault.updateCredentialTokens(cred.ownerId!, cred.id, newSecret, metadataUpdates);
              if (newAccountLabel && newAccountLabel !== cred.accountLabel) {
                if (this.#getEpoch(cred.id) !== epoch || !attempt.isActive()) {
                  return;
                }
                this.#vault.updateCredentialLabel(cred.ownerId!, cred.id, newAccountLabel);
                cred.accountLabel = newAccountLabel;
              }
            },
          };
          const fetched = await adapter.fetchUsage(cred, ctx);
          attempt.throwIfInactive();
          if (this.#getEpoch(cred.id) !== epoch) {
            return null;
          }
          if (fetched.error) {
            throw new Error(fetched.error);
          }
          if (this.#getEpoch(cred.id) !== epoch) {
            return null;
          }
          return attempt.commit(() => this.#saveSuccessfulReport(cred, fetched, daemon));
        });
      } catch (error) {
        if (this.#getEpoch(cred.id) !== epoch) {
          return null;
        }
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
        if (this.#inFlight.get(cred.id) === promise) {
          this.#inFlight.delete(cred.id);
        }
      }
    });

    this.#inFlight.set(cred.id, promise);
    return promise;
  }


  #saveSuccessfulReport(credential: StoredCredential, fetched: UsageReport, daemon: boolean): UsageReport {
    const fetchedAt = fetched.fetchedAt ?? Date.now();
    const report: UsageReport = {
      ...fetched,
      ownerId: credential.ownerId,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt,
      health: "healthy",
      stale: false,
      source: "live",
      lastGoodFetchedAt: fetchedAt,
    };
    if (daemon) this.#vault.saveUsageSnapshotInternal(report);
    else this.#vault.saveUsageSnapshot(credential.ownerId, report);

    for (const listener of this.#listeners) {
      try {
        listener(report);
      } catch {}
    }
    return report;
  }

  pollAll(): Promise<UsageReport[]> {
    if (this.#sweepInFlight) return this.#sweepInFlight;

    let sweep!: Promise<UsageReport[]>;
    sweep = this.#runSweep().finally(() => {
      if (this.#sweepInFlight === sweep) {
        this.#sweepInFlight = undefined;
      }
    });
    this.#sweepInFlight = sweep;
    return sweep;
  }

  async #runSweep(): Promise<UsageReport[]> {
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

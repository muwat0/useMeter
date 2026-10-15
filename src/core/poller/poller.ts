import { performance } from "node:perf_hooks";
import { randomUUID } from "node:crypto";
import type { StorageVault } from "../storage/vault";
import type { ProviderRegistry } from "../providers/registry";
import type { CredentialRef, InputCredential, StoredCredential, UsageReport } from "../../types";


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
  maxConcurrentGlobal?: number;
  maxConcurrentPerProvider?: number;
  minProviderIntervalMs?: number;
  maxQueuedJobs?: number;
  admissionTimeoutMs?: number;
}

export interface PollerOperationalStatus {
  running: boolean;
  sweepInProgress: boolean;
  lastSweepStatus: "never" | "running" | "ok" | "degraded" | "error";
  lastSweepDurationMs: number | null;
  lastSweepCompletedAt: number | null;
  consecutiveSweepFailures: number;
}

export type PollerAdmissionErrorCode = "QUEUE_FULL" | "ADMISSION_TIMEOUT";

export class PollerAdmissionError extends Error {
  readonly code: PollerAdmissionErrorCode;

  constructor(code: PollerAdmissionErrorCode, message: string) {
    super(message);
    this.name = "PollerAdmissionError";
    this.code = code;
  }
}

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;
const DEFAULT_POLL_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_CONCURRENT_GLOBAL = 4;
const DEFAULT_MAX_CONCURRENT_PER_PROVIDER = 1;
const DEFAULT_MIN_PROVIDER_INTERVAL_MS = 4_000;
const DEFAULT_MAX_QUEUED_JOBS = 256;
const DEFAULT_ADMISSION_TIMEOUT_MS = 30_000;
// Bound sweep producers to the default registry size; workers also drain custom provider groups.
const MAX_PROVIDER_GROUP_WORKERS = 17;
const MAX_TIMER_DELAY_MS = 2_147_483_647;

type ProviderDispatch = <T>(
  operation: (
    markDispatched: () => void,
    skipDispatch: () => void,
    signal: AbortSignal,
  ) => Promise<T> | T,
  signal?: AbortSignal,
) => Promise<T>;

type CredentialPollScope = Pick<CredentialRef, "id" | "ownerId">;

interface ProviderPoolJob {
  providerId: string;
  credentialScope?: CredentialPollScope;
  ownerId?: string;
  signal: AbortSignal;
  controller: AbortController;
  externalSignal?: AbortSignal;
  operation: (dispatch: ProviderDispatch) => Promise<unknown> | unknown;
  promise: Promise<unknown>;
  resolve(value: unknown): void;
  reject(reason: unknown): void;
  admissionDeadlineAt: number;
  state: "queued" | "admitted" | "dispatched" | "finished";
  onAbort?: () => void;
  onExternalAbort?: () => void;
}

class ProviderRequestPool {
  readonly #maxConcurrentGlobal: number;
  readonly #maxConcurrentPerProvider: number;
  readonly #minProviderIntervalMs: number;
  readonly #maxQueuedJobs: number;
  readonly #admissionTimeoutMs: number;
  readonly #queue: ProviderPoolJob[] = [];
  readonly #credentialJobs = new Map<string, Map<string, ProviderPoolJob>>();
  readonly #ownerJobs = new Map<string, Set<ProviderPoolJob>>();
  readonly #activeByProvider = new Map<string, number>();
  readonly #pendingProviders = new Map<string, ProviderPoolJob>();
  readonly #lastDispatchAt = new Map<string, number>();
  #activeGlobal = 0;
  #wakeTimer?: Timer;

  constructor(
    maxConcurrentGlobal: number,
    maxConcurrentPerProvider: number,
    minProviderIntervalMs: number,
    maxQueuedJobs: number,
    admissionTimeoutMs: number,
  ) {
    this.#maxConcurrentGlobal = maxConcurrentGlobal;
    this.#maxConcurrentPerProvider = maxConcurrentPerProvider;
    this.#minProviderIntervalMs = minProviderIntervalMs;
    this.#maxQueuedJobs = maxQueuedJobs;
    this.#admissionTimeoutMs = admissionTimeoutMs;
  }

  run<T>(
    providerId: string,
    externalSignal: AbortSignal | undefined,
    operation: (dispatch: ProviderDispatch) => Promise<T> | T,
    credentialScope?: CredentialPollScope,
    ownerId = credentialScope?.ownerId,
  ): Promise<T> {
    try {
      externalSignal?.throwIfAborted();
    } catch (error) {
      return Promise.reject(error);
    }
    this.#expireQueued(performance.now());

    if (credentialScope) {
      const existing = this.#credentialJobs.get(credentialScope.id)?.get(credentialScope.ownerId);
      if (existing) return existing.promise as Promise<T>;
    }
    if (this.#queue.length >= this.#maxQueuedJobs) {
      return Promise.reject(new PollerAdmissionError(
        "QUEUE_FULL",
        "Poller queue is full; retry the request later.",
      ));
    }

    const { promise, resolve, reject } = Promise.withResolvers<T>();
    const controller = new AbortController();
    const job: ProviderPoolJob = {
      providerId,
      credentialScope,
      ownerId,
      signal: controller.signal,
      controller,
      externalSignal,
      operation: dispatch => operation(dispatch),
      promise,
      resolve: value => resolve(value as T),
      reject,
      admissionDeadlineAt: performance.now() + this.#admissionTimeoutMs,
      state: "queued",
    };
    if (credentialScope) {
      let jobsByOwner = this.#credentialJobs.get(credentialScope.id);
      if (!jobsByOwner) {
        jobsByOwner = new Map<string, ProviderPoolJob>();
        this.#credentialJobs.set(credentialScope.id, jobsByOwner);
      }
      jobsByOwner.set(credentialScope.ownerId, job);
    }
    if (ownerId) {
      let jobs = this.#ownerJobs.get(ownerId);
      if (!jobs) {
        jobs = new Set<ProviderPoolJob>();
        this.#ownerJobs.set(ownerId, jobs);
      }
      jobs.add(job);
    }
    job.onAbort = () => {
      if (job.state !== "queued") return;
      this.#removeQueued(job);
      job.state = "finished";
      this.#forgetCredentialJob(job);
      this.#forgetOwnerJob(job);
      this.#detachSignals(job);
      reject(job.signal.reason ?? new Error("Provider request canceled"));
      this.#drain();
    };
    job.onExternalAbort = () => {
      if (!controller.signal.aborted) {
        controller.abort(externalSignal?.reason ?? new Error("Provider request canceled"));
      }
    };
    controller.signal.addEventListener("abort", job.onAbort, { once: true });
    externalSignal?.addEventListener("abort", job.onExternalAbort, { once: true });
    this.#queue.push(job);
    if (controller.signal.aborted) {
      job.onAbort();
      return promise;
    }
    this.#drain();
    return promise;
  }

  invalidateCredential(credentialId: string): void {
    const jobsByOwner = this.#credentialJobs.get(credentialId);
    if (!jobsByOwner) return;
    for (const [ownerId, job] of jobsByOwner) {
      if (job.state === "dispatched") jobsByOwner.delete(ownerId);
    }
    if (jobsByOwner.size === 0) this.#credentialJobs.delete(credentialId);
  }

  cancelOwner(ownerId: string): number {
    const jobs = this.#ownerJobs.get(ownerId);
    if (!jobs) return 0;
    let cancelled = 0;
    for (const job of Array.from(jobs)) {
      cancelled++;
      if (!job.signal.aborted) job.controller.abort(new Error("Owner authorization was revoked"));
      if (job.state === "queued") job.onAbort?.();
    }
    this.#drain();
    return cancelled;
  }


  #removeQueued(job: ProviderPoolJob): void {
    const index = this.#queue.indexOf(job);
    if (index !== -1) this.#queue.splice(index, 1);
  }

  #forgetCredentialJob(job: ProviderPoolJob): void {
    const scope = job.credentialScope;
    if (!scope) return;
    const jobsByOwner = this.#credentialJobs.get(scope.id);
    if (jobsByOwner?.get(scope.ownerId) !== job) return;
    jobsByOwner.delete(scope.ownerId);
    if (jobsByOwner.size === 0) this.#credentialJobs.delete(scope.id);
  }
  #forgetOwnerJob(job: ProviderPoolJob): void {
    if (!job.ownerId) return;
    const jobs = this.#ownerJobs.get(job.ownerId);
    jobs?.delete(job);
    if (jobs?.size === 0) this.#ownerJobs.delete(job.ownerId);
  }

  #detachSignals(job: ProviderPoolJob): void {
    if (job.onAbort) job.signal.removeEventListener("abort", job.onAbort);
    if (job.externalSignal && job.onExternalAbort) {
      job.externalSignal.removeEventListener("abort", job.onExternalAbort);
    }
  }


  #isReady(job: ProviderPoolJob, now: number): boolean {
    if (this.#pendingProviders.has(job.providerId)) return false;
    if ((this.#activeByProvider.get(job.providerId) ?? 0) >= this.#maxConcurrentPerProvider) {
      return false;
    }
    const lastDispatchAt = this.#lastDispatchAt.get(job.providerId);
    return lastDispatchAt === undefined ||
      lastDispatchAt + this.#minProviderIntervalMs <= now;
  }

  #dispatch<T>(
    job: ProviderPoolJob,
    operation: (markDispatched: () => void, skipDispatch: () => void, signal: AbortSignal) => Promise<T> | T,
    signal: AbortSignal,
  ): Promise<T> {
    if (signal?.aborted) {
      this.#skipDispatch(job);
      return Promise.reject(signal.reason ?? new Error("Provider request canceled"));
    }

    let admissionPending = true;
    const markDispatched = (): void => {
      if (!admissionPending) return;
      admissionPending = false;
      job.state = "dispatched";
      if (this.#pendingProviders.get(job.providerId) === job) {
        this.#pendingProviders.delete(job.providerId);
      }
      this.#lastDispatchAt.set(job.providerId, performance.now());
      this.#activeByProvider.set(
        job.providerId,
        (this.#activeByProvider.get(job.providerId) ?? 0) + 1,
      );
      this.#drain();
    };
    const skipDispatch = (): void => {
      if (!admissionPending) return;
      admissionPending = false;
      this.#skipDispatch(job);
    };

    let result: Promise<T> | T;
    try {
      result = operation(markDispatched, skipDispatch, signal);
    } catch (error) {
      result = Promise.reject(error);
    }
    return Promise.resolve(result).finally(() => {
      if (admissionPending) skipDispatch();
    });
  }

  #skipDispatch(job: ProviderPoolJob): void {
    if (this.#pendingProviders.get(job.providerId) === job) {
      this.#pendingProviders.delete(job.providerId);
    }
    this.#drain();
  }

  #drain(): void {
    let now = performance.now();
    this.#expireQueued(now);
    while (this.#activeGlobal < this.#maxConcurrentGlobal) {
      const index = this.#queue.findIndex(job => this.#isReady(job, now));
      if (index === -1) break;
      const [job] = this.#queue.splice(index, 1);
      if (!job) break;
      if (job.signal.aborted) {
        job.state = "finished";
        this.#forgetCredentialJob(job);
        this.#forgetOwnerJob(job);
        this.#detachSignals(job);
        job.reject(job.signal.reason ?? new Error("Provider request canceled"));
        continue;
      }

      job.state = "admitted";
      if (job.onAbort) job.signal.removeEventListener("abort", job.onAbort);
      this.#activeGlobal++;
      this.#pendingProviders.set(job.providerId, job);
      const dispatch: ProviderDispatch = (operation, signal = job.signal) =>
        this.#dispatch(job, operation, signal);
      let result: Promise<unknown> | unknown;
      try {
        result = job.operation(dispatch);
      } catch (error) {
        result = Promise.reject(error);
      }
      Promise.resolve(result)
        .then(job.resolve, job.reject)
        .finally(() => this.#finish(job));
      now = performance.now();
    }
    this.#scheduleWake(now);
  }

  #expireQueued(now: number): void {
    for (let index = this.#queue.length - 1; index >= 0; index--) {
      const job = this.#queue[index];
      if (!job || job.admissionDeadlineAt > now) continue;
      this.#queue.splice(index, 1);
      job.state = "finished";
      this.#forgetCredentialJob(job);
      this.#forgetOwnerJob(job);
      this.#detachSignals(job);
      job.reject(new PollerAdmissionError(
        "ADMISSION_TIMEOUT",
        "Provider admission timed out before dispatch.",
      ));
    }
  }

  #scheduleWake(now: number): void {
    if (this.#wakeTimer) {
      clearTimeout(this.#wakeTimer);
      this.#wakeTimer = undefined;
    }
    if (this.#queue.length === 0) return;

    let wakeAt = Number.POSITIVE_INFINITY;
    for (const job of this.#queue) {
      wakeAt = Math.min(wakeAt, job.admissionDeadlineAt);
      if (this.#pendingProviders.has(job.providerId)) continue;
      if ((this.#activeByProvider.get(job.providerId) ?? 0) >= this.#maxConcurrentPerProvider) {
        continue;
      }
      const lastDispatchAt = this.#lastDispatchAt.get(job.providerId);
      if (lastDispatchAt !== undefined) {
        const providerReadyAt = lastDispatchAt + this.#minProviderIntervalMs;
        if (providerReadyAt > now) wakeAt = Math.min(wakeAt, providerReadyAt);
      }
    }
    if (!Number.isFinite(wakeAt)) return;
    const delayMs = Math.max(1, Math.min(MAX_TIMER_DELAY_MS, Math.ceil(wakeAt - now)));
    this.#wakeTimer = setTimeout(() => {
      this.#wakeTimer = undefined;
      this.#drain();
    }, delayMs);
  }

  #finish(job: ProviderPoolJob): void {
    if (job.state === "finished" || job.state === "queued") return;
    if (job.state === "dispatched") {
      const activeForProvider = (this.#activeByProvider.get(job.providerId) ?? 1) - 1;
      if (activeForProvider === 0) this.#activeByProvider.delete(job.providerId);
      else this.#activeByProvider.set(job.providerId, activeForProvider);
    } else {
      if (this.#pendingProviders.get(job.providerId) === job) {
        this.#pendingProviders.delete(job.providerId);
      }
    }
    job.state = "finished";
    this.#activeGlobal--;
    this.#forgetCredentialJob(job);
    this.#drain();
    this.#forgetOwnerJob(job);
    this.#detachSignals(job);
  }
}


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
  readonly #providerPool: ProviderRequestPool;
  readonly #intervalMs: number;
  readonly #pollTimeoutMs: number;
  readonly #credentialEpochs: Map<string, number> = new Map();
  readonly #listeners: Set<ReportListener> = new Set();
  #timer?: Timer;
  #running = false;
  #sweepInFlight?: Promise<UsageReport[]>;
  #lastSweepStatus: "never" | "running" | "ok" | "degraded" | "error" = "never";
  #lastSweepDurationMs: number | null = null;
  #lastSweepCompletedAt: number | null = null;
  #consecutiveSweepFailures = 0;
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
    const maxConcurrentGlobal = options.maxConcurrentGlobal ?? DEFAULT_MAX_CONCURRENT_GLOBAL;
    if (!Number.isSafeInteger(maxConcurrentGlobal) || maxConcurrentGlobal < 1) {
      throw new RangeError("maxConcurrentGlobal must be a positive integer");
    }
    const maxConcurrentPerProvider =
      options.maxConcurrentPerProvider ?? DEFAULT_MAX_CONCURRENT_PER_PROVIDER;
    if (!Number.isSafeInteger(maxConcurrentPerProvider) || maxConcurrentPerProvider < 1) {
      throw new RangeError("maxConcurrentPerProvider must be a positive integer");
    }
    const minProviderIntervalMs =
      options.minProviderIntervalMs ?? DEFAULT_MIN_PROVIDER_INTERVAL_MS;
    if (
      !Number.isInteger(minProviderIntervalMs) ||
      minProviderIntervalMs < 0 ||
      minProviderIntervalMs > MAX_TIMER_DELAY_MS
    ) {
      throw new RangeError(`minProviderIntervalMs must be an integer between 0 and ${MAX_TIMER_DELAY_MS}`);
    }
    const maxQueuedJobs = options.maxQueuedJobs ?? DEFAULT_MAX_QUEUED_JOBS;
    if (!Number.isSafeInteger(maxQueuedJobs) || maxQueuedJobs < 1) {
      throw new RangeError("maxQueuedJobs must be a positive integer");
    }
    const admissionTimeoutMs = options.admissionTimeoutMs ?? DEFAULT_ADMISSION_TIMEOUT_MS;
    if (
      !Number.isInteger(admissionTimeoutMs) ||
      admissionTimeoutMs < 1 ||
      admissionTimeoutMs > MAX_TIMER_DELAY_MS
    ) {
      throw new RangeError(`admissionTimeoutMs must be an integer between 1 and ${MAX_TIMER_DELAY_MS}`);
    }
    this.#vault = vault;
    this.#registry = registry;
    this.#providerPool = new ProviderRequestPool(
      maxConcurrentGlobal,
      maxConcurrentPerProvider,
      minProviderIntervalMs,
      maxQueuedJobs,
      admissionTimeoutMs,
    );
    this.#intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.#pollTimeoutMs = pollTimeoutMs;
  }
  #canonicalProviderId(provider: string): string {
    return this.#registry.find(provider)?.id ?? provider.toLowerCase();
  }
  #credentialStillOwnedBy(ref: CredentialRef): boolean {
    const current = this.#vault.getCredentialRefInternal(ref.id);
    return current !== null && current.ownerId === ref.ownerId;
  }
  #getEpoch(credentialId: string): number {
    return this.#credentialEpochs.get(credentialId) ?? 0;
  }

  #bumpEpoch(credentialId: string): number {
    const next = this.#getEpoch(credentialId) + 1;
    this.#credentialEpochs.set(credentialId, next);
    this.#providerPool.invalidateCredential(credentialId);
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
    // Periodic sweeps share bounded provider dispatch with manual polling.
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

  cancelOwner(ownerId: string): number {
    return this.#providerPool.cancelOwner(ownerId);
  }

  async pollCredential(
    ownerId: string,
    credentialId: string,
    context: CredentialValidationContext = {},
  ): Promise<UsageReport | null> {
    const ref = this.#vault.getCredentialRef(ownerId, credentialId);
    if (!ref || ref.ownerId !== ownerId) return null;
    return this.#scheduleCredentialPoll(ref, false, context);
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

    return this.#providerPool.run(
      this.#canonicalProviderId(input.provider),
      context.signal,
      dispatch => dispatch((markDispatched, _skipDispatch, dispatchSignal) =>
        this.#runWithDeadline(dispatchSignal, async attempt => {
        markDispatched();
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
        }),
      ),
      undefined,
      ownerId,
    );
  }

  async pollUser(
    ownerId: string,
    context: CredentialValidationContext = {},
  ): Promise<UsageReport[]> {
    return this.#pollCredentialRefs(this.#vault.listCredentialRefs(ownerId), false, context);
  }

  #scheduleCredentialPoll(
    ref: CredentialRef,
    daemon: boolean,
    context: CredentialValidationContext = {},
  ): Promise<UsageReport | null> {
    return this.#providerPool.run(
      this.#canonicalProviderId(ref.provider),
      context.signal,
      dispatch => dispatch((markDispatched, skipDispatch, dispatchSignal) =>
        this.#pollCredentialInternal(
          ref,
          daemon,
          markDispatched,
          skipDispatch,
          dispatchSignal,
          context.beforeCommit,
        ),
      ),
      ref,
    );
  }

  async #pollCredentialInternal(
    ref: CredentialRef,
    daemon: boolean,
    markDispatched: () => void,
    skipDispatch: () => void,
    dispatchSignal: AbortSignal,
    beforeCommit?: () => boolean,
  ): Promise<UsageReport | null> {
    let dispatchedCredential: StoredCredential | undefined;
    let dispatchedEpoch: number | undefined;
    let credentialReadFailed = false;
    let promise!: Promise<UsageReport | null>;
    promise = Promise.resolve().then(async () => {
      try {
        return await this.#runWithDeadline(dispatchSignal, async attempt => {
          let credential: StoredCredential | null;
          try {
            credential = this.#vault.getCredentialInternal(ref.id);
          } catch (error) {
            credentialReadFailed = true;
            throw error;
          }
          if (!credential || (credential.ownerId ?? "") !== ref.ownerId) {
            skipDispatch();
            return null;
          }
          const adapter = this.#registry.find(credential.provider);
          if (!adapter) {
            skipDispatch();
            return null;
          }
          attempt.throwIfInactive();
          const epoch = this.#getEpoch(credential.id);
          dispatchedCredential = credential;
          dispatchedEpoch = epoch;
          const ctx = {
            signal: attempt.signal,
            onTokenRefresh: (
              newSecret: string,
              metadataUpdates?: Record<string, unknown>,
              newAccountLabel?: string,
            ) => {
              if (
                !this.#credentialStillOwnedBy(ref) ||
                this.#getEpoch(credential.id) !== epoch ||
                !attempt.isActive() ||
                (beforeCommit !== undefined && !beforeCommit())
              ) return;
              this.#vault.updateCredentialTokens(
                credential.ownerId!,
                credential.id,
                newSecret,
                metadataUpdates,
              );
              if (newAccountLabel && newAccountLabel !== credential.accountLabel) {
                if (
                  !this.#credentialStillOwnedBy(ref) ||
                  this.#getEpoch(credential.id) !== epoch ||
                  !attempt.isActive() ||
                  (beforeCommit !== undefined && !beforeCommit())
                ) {
                  return;
                }
                this.#vault.updateCredentialLabel(
                  credential.ownerId!,
                  credential.id,
                  newAccountLabel,
                );
                credential.accountLabel = newAccountLabel;
              }
            },
          };
          markDispatched();
          const fetched = await adapter.fetchUsage(credential, ctx);
          attempt.throwIfInactive();
          // The credential may have been reauthenticated or claimed while the adapter was in flight.
          if (!this.#credentialStillOwnedBy(ref) || this.#getEpoch(credential.id) !== epoch) return null;
          if (fetched.error) throw new Error(fetched.error);
          if (beforeCommit && !beforeCommit()) return null;
          return attempt.commit(() => this.#saveSuccessfulReport(credential, fetched, daemon));
        });
      } catch (error) {
        if (dispatchSignal.aborted) return null;
        if (credentialReadFailed) throw error;
        if (!this.#credentialStillOwnedBy(ref)) return null;
        const credential = dispatchedCredential;
        const epoch = dispatchedEpoch;
        if (!credential || epoch === undefined || this.#getEpoch(ref.id) !== epoch) {
          return null;
        }
        const errorMessage = error instanceof Error ? error.message : String(error);
        const lastGood = (credential.ownerId && !daemon)
          ? this.#vault.getLastSuccessfulUsage(credential.ownerId, credential.id)
          : this.#vault.getLastSuccessfulUsageInternal(credential.id);

        const now = Date.now();
        const fallbackReport: UsageReport = lastGood
          ? {
              ownerId: credential.ownerId ?? lastGood.ownerId,
              provider: credential.provider || lastGood.provider,
              credentialId: credential.id,
              accountLabel: credential.accountLabel || lastGood.accountLabel,
              fetchedAt: now,
              limits: lastGood.limits || [],
              error: errorMessage,
              health: "stale",
              stale: true,
              source: "stale",
              lastGoodFetchedAt: lastGood.lastGoodFetchedAt ?? lastGood.fetchedAt,
            }
          : {
              ownerId: credential.ownerId,
              provider: credential.provider,
              credentialId: credential.id,
              accountLabel: credential.accountLabel,
              fetchedAt: now,
              limits: [],
              error: errorMessage,
              health: "error",
              stale: false,
              source: "error",
            };
        if (beforeCommit && !beforeCommit()) return null;
        if (daemon) this.#vault.saveUsageSnapshotInternal(fallbackReport);
        else this.#vault.saveUsageSnapshot(credential.ownerId!, fallbackReport);
        return fallbackReport;
      }
    });
    return promise;
  }

  async #pollCredentialRefs(
    refs: CredentialRef[],
    daemon: boolean,
    context: CredentialValidationContext = {},
  ): Promise<UsageReport[]> {
    const groupsByProvider = new Map<string, number[]>();
    for (let index = 0; index < refs.length; index++) {
      const ref = refs[index]!;
      const providerId = this.#canonicalProviderId(ref.provider);
      let group = groupsByProvider.get(providerId);
      if (!group) {
        group = [];
        groupsByProvider.set(providerId, group);
      }
      group.push(index);
    }

    const groups = [...groupsByProvider.values()];
    const reportsByRef: Array<UsageReport | null> = new Array(refs.length).fill(null);
    const errors: unknown[] = [];
    let nextGroupIndex = 0;
    const runProducer = async (): Promise<void> => {
      while (nextGroupIndex < groups.length) {
        const group = groups[nextGroupIndex++]!;
        for (const refIndex of group) {
          try {
            const report = await this.#scheduleCredentialPoll(refs[refIndex]!, daemon, context);
            if (report) reportsByRef[refIndex] = report;
          } catch (error) {
            errors.push(error);
            break;
          }
        }
      }
    };

    const producerCount = Math.min(MAX_PROVIDER_GROUP_WORKERS, groups.length);
    const producers: Promise<void>[] = [];
    for (let index = 0; index < producerCount; index++) {
      producers.push(runProducer());
    }
    const settled = await Promise.allSettled(producers);
    for (const result of settled) {
      if (result.status === "rejected") errors.push(result.reason);
    }
    if (errors.length > 0) throw errors[0];
    return reportsByRef.filter((report): report is UsageReport => report !== null);
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

    const startedAt = performance.now();
    this.#lastSweepStatus = "running";
    let sweep!: Promise<UsageReport[]>;
    sweep = this.#runSweep().then(
      reports => {
        const failed = reports.some(report =>
          report.health === "error" || report.health === "stale" || Boolean(report.error)
        );
        this.#lastSweepStatus = failed ? "degraded" : "ok";
        this.#consecutiveSweepFailures = failed ? this.#consecutiveSweepFailures + 1 : 0;
        return reports;
      },
      error => {
        this.#lastSweepStatus = "error";
        this.#consecutiveSweepFailures += 1;
        throw error;
      },
    ).finally(() => {
      this.#lastSweepDurationMs = Math.max(0, performance.now() - startedAt);
      this.#lastSweepCompletedAt = Date.now();
      if (this.#sweepInFlight === sweep) {
        this.#sweepInFlight = undefined;
      }
    });
    this.#sweepInFlight = sweep;
    return sweep;
  }

  async #runSweep(): Promise<UsageReport[]> {
    return this.#pollCredentialRefs(this.#vault.listAllCredentialRefsInternal(), true);
  }

  isRunning(): boolean {
    return this.#running;
  }
  getOperationalStatus(): PollerOperationalStatus {
    return {
      running: this.#running,
      sweepInProgress: this.#sweepInFlight !== undefined,
      lastSweepStatus: this.#lastSweepStatus,
      lastSweepDurationMs: this.#lastSweepDurationMs,
      lastSweepCompletedAt: this.#lastSweepCompletedAt,
      consecutiveSweepFailures: this.#consecutiveSweepFailures,
    };
  }
}


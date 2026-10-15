import {
  DEFAULT_USAGE_SNAPSHOT_RETENTION_DAYS,
  type UsageSnapshotPruneReceipt,
  type StorageVault,
} from "./vault";

export const DEFAULT_USAGE_SNAPSHOT_RETENTION_INTERVAL_MS = 60 * 60 * 1_000;

export interface UsageSnapshotRetentionOptions {
  retentionDays?: number;
  intervalMs?: number;
}

export class UsageSnapshotRetention {
  readonly #vault: StorageVault;
  readonly #retentionDays: number;
  readonly #intervalMs: number;
  #timer?: Timer;
  #controller?: AbortController;
  #activeRun?: Promise<UsageSnapshotPruneReceipt>;
  #initialRun?: Promise<UsageSnapshotPruneReceipt>;
  #stopPromise?: Promise<void>;
  #started = false;
  #stopped = false;

  constructor(vault: StorageVault, options: UsageSnapshotRetentionOptions = {}) {
    const retentionDays = options.retentionDays ?? DEFAULT_USAGE_SNAPSHOT_RETENTION_DAYS;
    if (
      !Number.isSafeInteger(retentionDays) ||
      retentionDays < 1 ||
      !Number.isSafeInteger(retentionDays * 24 * 60 * 60 * 1_000)
    ) {
      throw new RangeError("retentionDays must be a positive safe integer.");
    }
    const intervalMs = options.intervalMs ?? DEFAULT_USAGE_SNAPSHOT_RETENTION_INTERVAL_MS;
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 1 || intervalMs > 2_147_483_647) {
      throw new RangeError("intervalMs must be a positive safe integer within the timer range.");
    }
    this.#vault = vault;
    this.#retentionDays = retentionDays;
    this.#intervalMs = intervalMs;
  }

  start(): Promise<UsageSnapshotPruneReceipt> {
    if (this.#stopped) return Promise.reject(new Error("Snapshot retention has been stopped."));
    if (this.#started) return this.#initialRun!;

    this.#started = true;
    this.#timer = setInterval(() => {
      if (this.#stopped) return;
      void this.#run().catch((error: unknown) => {
        if (error instanceof Error && error.name === "AbortError") return;
        console.error("Usage snapshot retention failed:", error);
      });
    }, this.#intervalMs);
    this.#timer.unref();
    this.#initialRun = this.#run();
    return this.#initialRun;
  }

  stop(): Promise<void> {
    if (this.#stopPromise) return this.#stopPromise;
    this.#stopped = true;
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }
    this.#controller?.abort();
    const activeRun = this.#activeRun;
    this.#stopPromise = activeRun
      ? activeRun.then(
          () => undefined,
          (error: unknown) => {
            if (error instanceof Error && error.name === "AbortError") return;
            throw error;
          },
        )
      : Promise.resolve();
    return this.#stopPromise;
  }

  #run(): Promise<UsageSnapshotPruneReceipt> {
    if (this.#activeRun) return this.#activeRun;
    const controller = new AbortController();
    this.#controller = controller;
    const run = this.#vault.pruneUsageSnapshots({
      retentionDays: this.#retentionDays,
      signal: controller.signal,
    });
    this.#activeRun = run;
    void run.then(
      () => this.#finishRun(run, controller),
      () => this.#finishRun(run, controller),
    );
    return run;
  }

  #finishRun(
    run: Promise<UsageSnapshotPruneReceipt>,
    controller: AbortController,
  ): void {
    if (this.#activeRun !== run) return;
    this.#activeRun = undefined;
    if (this.#controller === controller) this.#controller = undefined;
  }
}

import { randomUUID } from "node:crypto";

export type OAuthSessionStatus = "pending" | "complete" | "error";
export type OAuthSessionEndReason = "cancelled" | "expired" | "terminal" | "purged";

export interface OAuthSession<T> {
  sessionId: string;
  ownerId: string;
  provider: string;
  status: OAuthSessionStatus;
  createdAt: number;
  expiresAt: number;
  terminalExpiresAt?: number;
  error?: string;
  accountLabel?: string;
  data: T;
  signal: AbortSignal;
}

export type OAuthDeviceClaim<T> =
  | { status: "claimed"; session: OAuthSession<T> }
  | { status: "busy" };

interface StoredOAuthSession<T> extends OAuthSession<T> {
  controller: AbortController;
  reserved: boolean;
  processing: boolean;
  commitAdmitted: boolean;
  bindingKey?: string;
  cleaned: boolean;
}

export interface OAuthSessionStoreOptions<T> {
  now?: () => number;
  maxPerOwner?: number;
  maxEntries?: number;
  pendingTtlMs?: number;
  terminalTtlMs?: number;
  onEnd?: (session: OAuthSession<T>, reason: OAuthSessionEndReason) => void;
}

export class OAuthCapacityError extends Error {
  constructor() {
    super("OAuth session capacity reached");
    this.name = "OAuthCapacityError";
  }
}

const DEFAULT_MAX_PER_OWNER = 5;
const DEFAULT_MAX_ENTRIES = 1_000;
const DEFAULT_PENDING_TTL_MS = 10 * 60 * 1_000;
const DEFAULT_TERMINAL_TTL_MS = 60 * 1_000;
const MAX_TIMER_DELAY_MS = 2_147_000_000;

/** In-memory, bounded, owner-bound OAuth sessions and device-code reservations. */
export class OAuthSessionStore<T = Record<string, never>> {
  readonly #entries = new Map<string, StoredOAuthSession<T>>();
  readonly #deviceBindings = new Map<string, string>();
  readonly #now: () => number;
  readonly #maxPerOwner: number;
  readonly #maxEntries: number;
  readonly #pendingTtlMs: number;
  readonly #terminalTtlMs: number;
  readonly #onEnd?: OAuthSessionStoreOptions<T>["onEnd"];
  #timer?: ReturnType<typeof setTimeout>;

  constructor(options: OAuthSessionStoreOptions<T> = {}) {
    this.#now = options.now ?? Date.now;
    this.#maxPerOwner = options.maxPerOwner ?? DEFAULT_MAX_PER_OWNER;
    this.#maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.#pendingTtlMs = options.pendingTtlMs ?? DEFAULT_PENDING_TTL_MS;
    this.#terminalTtlMs = options.terminalTtlMs ?? DEFAULT_TERMINAL_TTL_MS;
    this.#onEnd = options.onEnd;
  }

  /** Reserves capacity before any provider or callback-listener work begins. */
  reserve(ownerId: string, provider: string, data: T): OAuthSession<T> {
    this.sweepExpired();
    let ownerCount = 0;
    for (const entry of this.#entries.values()) {
      if (entry.ownerId === ownerId) ownerCount++;
    }
    if (ownerCount >= this.#maxPerOwner || this.#entries.size >= this.#maxEntries) {
      throw new OAuthCapacityError();
    }

    const controller = new AbortController();
    const now = this.#now();
    const session: StoredOAuthSession<T> = {
      sessionId: randomUUID(),
      ownerId,
      provider,
      status: "pending",
      createdAt: now,
      expiresAt: now + this.#pendingTtlMs,
      data,
      signal: controller.signal,
      controller,
      reserved: true,
      processing: false,
      commitAdmitted: false,
      cleaned: false,
    };
    this.#entries.set(session.sessionId, session);
    this.#scheduleCleanup();
    return session;
  }

  /** Activates a reservation with the provider-visible session id and optional device binding. */
  activate(
    session: OAuthSession<T>,
    sessionId: string,
    data: T,
    options: { bindingId?: string; expiresInMs?: number } = {},
  ): boolean {
    this.sweepExpired();
    const entry = this.#current(session);
    if (!entry || !entry.reserved || entry.signal.aborted || !sessionId) return false;
    if (sessionId !== entry.sessionId && this.#entries.has(sessionId)) return false;

    const requestedExpiresInMs = options.expiresInMs ?? this.#pendingTtlMs;
    const expiresInMs = Number.isFinite(requestedExpiresInMs)
      ? Math.min(this.#pendingTtlMs, Math.max(0, requestedExpiresInMs))
      : this.#pendingTtlMs;
    const bindingKey = options.bindingId === undefined
      ? undefined
      : this.#bindingKey(entry.provider, options.bindingId);
    if (bindingKey && this.#deviceBindings.has(bindingKey)) return false;

    this.#entries.delete(entry.sessionId);
    entry.sessionId = sessionId;
    entry.data = data;
    entry.reserved = false;
    entry.expiresAt = Math.min(entry.createdAt + this.#pendingTtlMs, this.#now() + expiresInMs);
    entry.bindingKey = bindingKey;
    this.#entries.set(sessionId, entry);
    if (bindingKey) this.#deviceBindings.set(bindingKey, sessionId);
    this.#scheduleCleanup();
    return true;
  }

  get(sessionId: string): OAuthSession<T> | undefined {
    this.sweepExpired();
    return this.#entries.get(sessionId);
  }

  getOwned(sessionId: string, ownerId: string): OAuthSession<T> | undefined {
    const session = this.get(sessionId);
    return session?.ownerId === ownerId ? session : undefined;
  }

  /** Atomically claims one pending session for callback/manual completion. */
  claim(session: OAuthSession<T>): boolean {
    this.sweepExpired();
    const entry = this.#current(session);
    if (!entry || entry.reserved || entry.status !== "pending" || entry.processing || entry.signal.aborted) return false;
    entry.processing = true;
    return true;
  }

  /** Looks up a provider+device-id binding and claims it once for its owner. */
  claimDevice(provider: string, bindingId: string, ownerId: string): OAuthDeviceClaim<T> | undefined {
    this.sweepExpired();
    const sessionId = this.#deviceBindings.get(this.#bindingKey(provider, bindingId));
    if (!sessionId) return undefined;
    const entry = this.#entries.get(sessionId);
    if (
      !entry ||
      entry.ownerId !== ownerId ||
      entry.reserved ||
      entry.status !== "pending" ||
      entry.signal.aborted
    ) {
      return undefined;
    }
    if (entry.processing) return { status: "busy" };
    entry.processing = true;
    return { status: "claimed", session: entry };
  }

  releaseClaim(session: OAuthSession<T>): boolean {
    const entry = this.#current(session);
    if (
      !entry ||
      !entry.processing ||
      entry.commitAdmitted ||
      entry.status !== "pending" ||
      entry.signal.aborted
    ) return false;
    entry.processing = false;
    return true;
  }

  isActive(session: OAuthSession<T>): boolean {
    this.sweepExpired();
    const entry = this.#current(session);
    return !!entry && !entry.reserved && entry.status === "pending" && !entry.signal.aborted;
  }

  /** Admits the claimed session to its synchronous, irreversible credential commit. */
  admitCommit(session: OAuthSession<T>): boolean {
    this.sweepExpired();
    const entry = this.#current(session);
    if (
      !entry ||
      entry.reserved ||
      entry.status !== "pending" ||
      !entry.processing ||
      entry.signal.aborted ||
      entry.commitAdmitted
    ) {
      return false;
    }
    entry.commitAdmitted = true;
    this.#scheduleCleanup();
    return true;
  }

  complete(session: OAuthSession<T>, accountLabel?: string): boolean {
    return this.#finish(session, "complete", undefined, accountLabel);
  }

  fail(session: OAuthSession<T>, error: string): boolean {
    return this.#finish(session, "error", error);
  }

  /** Cancels the owner's session unless its synchronous commit is admitted. */
  cancel(sessionId: string, ownerId: string): boolean {
    this.sweepExpired();
    const entry = this.#entries.get(sessionId);
    if (!entry || entry.ownerId !== ownerId || entry.commitAdmitted) return false;
    this.#remove(entry, "cancelled");
    this.#scheduleCleanup();
    return true;
  }

  /** Cancels every pending or reserved session for an owner, preserving admitted synchronous commits. */
  cancelOwner(ownerId: string): number {
    this.sweepExpired();
    let cancelled = 0;
    for (const entry of this.#entries.values()) {
      if (entry.ownerId !== ownerId || entry.status !== "pending" || entry.commitAdmitted) continue;
      this.#remove(entry, "cancelled");
      cancelled++;
    }
    this.#scheduleCleanup();
    return cancelled;
  }

  /** Deterministic clock seam used by tests and the automatic unref'ed timer. */
  sweepExpired(): number {
    const now = this.#now();
    let removed = 0;
    for (const entry of this.#entries.values()) {
      if (entry.status !== "pending") {
        if (entry.terminalExpiresAt !== undefined && now >= entry.terminalExpiresAt) {
          this.#remove(entry, "purged");
          removed++;
        }
        continue;
      }
      if (entry.commitAdmitted) continue;
      if (now < entry.expiresAt) continue;
      if (entry.reserved) {
        this.#remove(entry, "expired");
        removed++;
        continue;
      }
      if (!entry.signal.aborted) entry.controller.abort(new Error("OAuth session expired"));
      entry.status = "error";
      entry.error = "Authorization session expired";
      entry.terminalExpiresAt = entry.expiresAt + this.#terminalTtlMs;
      entry.processing = false;
      this.#removeBinding(entry);
      this.#end(entry, "expired");
      if (now >= entry.terminalExpiresAt) {
        this.#remove(entry, "purged");
        removed++;
      }
    }
    this.#scheduleCleanup();
    return removed;
  }

  #finish(
    session: OAuthSession<T>,
    status: "complete" | "error",
    error?: string,
    accountLabel?: string,
  ): boolean {
    this.sweepExpired();
    const entry = this.#current(session);
    if (!entry || entry.reserved || entry.status !== "pending" || entry.signal.aborted) return false;
    entry.status = status;
    entry.error = error;
    entry.accountLabel = accountLabel;
    entry.terminalExpiresAt = this.#now() + this.#terminalTtlMs;
    entry.processing = false;
    entry.commitAdmitted = false;
    this.#removeBinding(entry);
    if (!entry.signal.aborted) entry.controller.abort(new Error(`OAuth session ${status}`));
    this.#end(entry, "terminal");
    this.#scheduleCleanup();
    return true;
  }

  #current(session: OAuthSession<T>): StoredOAuthSession<T> | undefined {
    const current = this.#entries.get(session.sessionId);
    return current === session ? current : undefined;
  }

  #bindingKey(provider: string, bindingId: string): string {
    return JSON.stringify([provider, bindingId]);
  }

  #removeBinding(entry: StoredOAuthSession<T>): void {
    if (entry.bindingKey && this.#deviceBindings.get(entry.bindingKey) === entry.sessionId) {
      this.#deviceBindings.delete(entry.bindingKey);
    }
    entry.bindingKey = undefined;
  }

  #end(entry: StoredOAuthSession<T>, reason: OAuthSessionEndReason): void {
    if (entry.cleaned) return;
    entry.cleaned = true;
    try {
      this.#onEnd?.(entry, reason);
    } catch {
      // Session removal and capacity release must not depend on cleanup callbacks.
    }
  }

  #remove(entry: StoredOAuthSession<T>, reason: OAuthSessionEndReason): void {
    if (this.#entries.get(entry.sessionId) !== entry) return;
    this.#entries.delete(entry.sessionId);
    this.#removeBinding(entry);
    if (!entry.signal.aborted) entry.controller.abort(new Error(`OAuth session ${reason}`));
    this.#end(entry, reason);
  }

  #scheduleCleanup(): void {
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    if (this.#entries.size === 0) return;

    let nextExpiry = Number.POSITIVE_INFINITY;
    for (const entry of this.#entries.values()) {
      if (entry.status === "pending" && entry.commitAdmitted) continue;
      const expiry = entry.status === "pending" ? entry.expiresAt : entry.terminalExpiresAt;
      if (expiry !== undefined && expiry < nextExpiry) nextExpiry = expiry;
    }
    if (!Number.isFinite(nextExpiry)) return;
    const delay = Math.min(MAX_TIMER_DELAY_MS, Math.max(1, nextExpiry - this.#now()));
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      this.sweepExpired();
    }, delay);
    this.#timer.unref?.();
  }
}

import { describe, expect, it, vi } from "bun:test";
import { OAuthCapacityError, OAuthSessionStore } from "../src/core/oauth/session-store";

type SessionData = { verifier?: string };

function activate(
  store: OAuthSessionStore<SessionData>,
  ownerId: string,
  provider: string,
  sessionId: string,
  bindingId?: string,
) {
  const session = store.reserve(ownerId, provider, {});
  const activated = store.activate(session, sessionId, { verifier: "synthetic-verifier" }, { bindingId });
  if (!activated) throw new Error("Synthetic session activation failed");
  return session;
}

describe("bounded OAuth sessions", () => {
  it("counts reservations, pending sessions, and terminal sessions against mixed owner/global limits", () => {
    let now = 1_000;
    const store = new OAuthSessionStore<SessionData>({
      now: () => now,
      maxPerOwner: 2,
      maxEntries: 3,
      pendingTtlMs: 1_000,
      terminalTtlMs: 60_000,
    });
    const browser = activate(store, "owner-a", "google", "browser-session");
    const device = activate(store, "owner-a", "copilot", "device-session", "shared-provider-code");
    const otherOwner = store.reserve("owner-b", "another-provider", {});

    expect(() => store.reserve("owner-a", "third-flow", {})).toThrow(OAuthCapacityError);
    expect(() => store.reserve("owner-c", "global-overflow", {})).toThrow(OAuthCapacityError);
    expect(store.complete(browser, "Synthetic account")).toBe(true);
    expect(browser.status).toBe("complete");
    expect(() => store.reserve("owner-a", "terminal-still-counts", {})).toThrow(OAuthCapacityError);

    expect(store.cancel(device.sessionId, "owner-a")).toBe(true);
    const replacement = store.reserve("owner-a", "replacement", {});
    expect(() => store.reserve("owner-c", "global-overflow", {})).toThrow(OAuthCapacityError);

    expect(store.cancel(replacement.sessionId, "owner-a")).toBe(true);
    expect(store.cancel(otherOwner.sessionId, "owner-b")).toBe(true);
    expect(store.cancel(browser.sessionId, "owner-a")).toBe(true);
    const failedInitiation = store.reserve("owner-a", "failed-initiation-released", {});
    expect(failedInitiation.ownerId).toBe("owner-a");
    expect(store.cancel(failedInitiation.sessionId, "owner-a")).toBe(true);
  });

  it("expires active work, retains its terminal result only until original deadline plus 60 seconds", () => {
    let now = 10_000;
    const ended: string[] = [];
    const store = new OAuthSessionStore<SessionData>({
      now: () => now,
      pendingTtlMs: 100,
      terminalTtlMs: 60_000,
      onEnd: (_session, reason) => ended.push(reason),
    });
    const session = activate(store, "owner-a", "google", "expires-at-boundary");
    expect(session.expiresAt).toBe(10_100);

    now = 10_100;
    const terminal = store.getOwned(session.sessionId, "owner-a");
    expect(terminal?.status).toBe("error");
    expect(terminal?.error).toBe("Authorization session expired");
    expect(terminal?.terminalExpiresAt).toBe(70_100);
    expect(terminal?.signal.aborted).toBe(true);
    expect(store.getOwned(session.sessionId, "owner-b")).toBeUndefined();

    now = 70_099;
    expect(store.get(session.sessionId)?.status).toBe("error");
    now = 70_100;
    expect(store.get(session.sessionId)).toBeUndefined();
    expect(ended).toEqual(["expired"]);
  });

  it("automatically expires and purges sessions without another request", () => {
    vi.useFakeTimers();
    let now = 0;
    try {
      const store = new OAuthSessionStore<SessionData>({
        now: () => now,
        pendingTtlMs: 100,
        terminalTtlMs: 60,
      });
      const session = activate(store, "owner", "google", "automatic-cleanup");
      now = 100;
      vi.advanceTimersByTime(100);
      expect(session.status).toBe("error");
      expect(session.signal.aborted).toBe(true);

      now = 160;
      vi.advanceTimersByTime(60);
      expect(store.get(session.sessionId)).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("expires an unbound reservation and releases both owner and global capacity", () => {
    let now = 5_000;
    const store = new OAuthSessionStore<SessionData>({
      now: () => now,
      maxPerOwner: 1,
      maxEntries: 1,
      pendingTtlMs: 100,
    });
    const reservation = store.reserve("owner", "codex", {});
    now += 100;
    expect(store.sweepExpired()).toBe(1);
    expect(reservation.signal.aborted).toBe(true);

    const replacement = store.reserve("owner", "copilot", {});
    expect(replacement.ownerId).toBe("owner");
    expect(store.cancel(replacement.sessionId, "owner")).toBe(true);
  });

  it("purges an expired session immediately after a clock jump beyond terminal retention", () => {
    let now = 5_000;
    const store = new OAuthSessionStore<SessionData>({
      now: () => now,
      pendingTtlMs: 100,
      terminalTtlMs: 60_000,
    });
    const session = activate(store, "owner", "google", "clock-jump");
    now = 70_000;

    expect(store.get(session.sessionId)).toBeUndefined();
    expect(store.sweepExpired()).toBe(0);
  });

  it("binds device identifiers to provider and owner, claims polls exclusively, and rejects replay", () => {
    const store = new OAuthSessionStore<SessionData>();
    const first = activate(store, "owner-a", "copilot", "copilot-session", "same-code");
    const otherProvider = activate(store, "owner-b", "xai", "xai-session", "same-code");

    expect(store.getOwned(first.sessionId, "owner-b")).toBeUndefined();
    expect(store.claimDevice("xai", "same-code", "owner-a")).toBeUndefined();
    expect(store.claimDevice("copilot", "same-code", "owner-b")).toBeUndefined();

    const claimed = store.claimDevice("copilot", "same-code", "owner-a");
    if (!claimed || claimed.status !== "claimed") throw new Error("Expected an exclusive device-poll claim");
    expect(claimed.session).toBe(first);
    expect(store.claimDevice("copilot", "same-code", "owner-a")).toEqual({ status: "busy" });
    expect(store.releaseClaim(first)).toBe(true);
    expect(store.claimDevice("copilot", "same-code", "owner-a")).toMatchObject({
      status: "claimed",
      session: first,
    });
    expect(store.complete(first, "Synthetic account")).toBe(true);
    expect(store.claimDevice("copilot", "same-code", "owner-a")).toBeUndefined();
    expect(store.get(first.sessionId)?.status).toBe("complete");

    expect(store.cancel(otherProvider.sessionId, "owner-b")).toBe(true);
    expect(store.cancel(first.sessionId, "owner-a")).toBe(true);
  });

  it("aborts canceled in-flight work, wipes secrets, and never lets its stale closure complete", () => {
    const store = new OAuthSessionStore<SessionData>({
      onEnd: session => { session.data.verifier = undefined; },
    });
    const session = activate(store, "owner-a", "devin", "cancelled-session");
    expect(store.claim(session)).toBe(true);
    expect(store.cancel(session.sessionId, "owner-b")).toBe(false);
    expect(store.cancel(session.sessionId, "owner-a")).toBe(true);
    expect(session.signal.aborted).toBe(true);
    expect(session.data.verifier).toBeUndefined();
    expect(store.complete(session, "Late account")).toBe(false);
    expect(store.get(session.sessionId)).toBeUndefined();
  });

  it("releases a failed activation reservation without evicting active entries", () => {
    const store = new OAuthSessionStore<SessionData>({ maxPerOwner: 2, maxEntries: 2 });
    const first = activate(store, "owner", "device", "first", "provider-id");
    const reservation = store.reserve("owner", "device", {});
    expect(store.activate(reservation, "second", {}, { bindingId: "provider-id" })).toBe(false);
    expect(store.cancel(reservation.sessionId, "owner")).toBe(true);
    expect(store.get(first.sessionId)).toBe(first);
    const replacement = store.reserve("owner", "replacement", {});
    expect(replacement.ownerId).toBe("owner");
    expect(store.cancel(replacement.sessionId, "owner")).toBe(true);
    expect(store.cancel(first.sessionId, "owner")).toBe(true);
  });

  it("admits one current claimed session through expiry until synchronous completion", () => {
    let now = 1_000;
    const store = new OAuthSessionStore<SessionData>({
      now: () => now,
      pendingTtlMs: 100,
      terminalTtlMs: 60_000,
    });
    const reservation = store.reserve("owner-a", "copilot", {});
    expect(store.admitCommit(reservation)).toBe(false);
    expect(store.cancel(reservation.sessionId, "owner-a")).toBe(true);
    const session = activate(store, "owner-a", "copilot", "commit-session", "provider-binding");
    const staleSession = { ...session };
    const foreignSession = { ...session, ownerId: "owner-b" };
    expect(store.admitCommit(foreignSession)).toBe(false);

    expect(store.admitCommit(session)).toBe(false);
    expect(store.admitCommit(staleSession)).toBe(false);
    expect(store.claim(session)).toBe(true);
    expect(store.admitCommit(staleSession)).toBe(false);
    expect(store.admitCommit(session)).toBe(true);
    expect(store.admitCommit(session)).toBe(false);
    expect(store.claimDevice("copilot", "provider-binding", "owner-a")).toEqual({ status: "busy" });
    expect(store.releaseClaim(session)).toBe(false);
    expect(store.cancel(session.sessionId, "owner-b")).toBe(false);
    expect(store.cancel(session.sessionId, "owner-a")).toBe(false);
    expect(session.signal.aborted).toBe(false);

    now = session.expiresAt;
    expect(store.sweepExpired()).toBe(0);
    expect(store.isActive(session)).toBe(true);
    expect(session.status).toBe("pending");
    expect(store.complete(session, "Synthetic account")).toBe(true);
    expect(session.status).toBe("complete");
    expect(session.terminalExpiresAt).toBe(now + 60_000);
  });

  it("rejects expired and canceled sessions before commit admission", () => {
    let now = 2_000;
    const store = new OAuthSessionStore<SessionData>({
      now: () => now,
      pendingTtlMs: 100,
    });
    const expired = activate(store, "owner", "google", "expired-before-commit");
    expect(store.claim(expired)).toBe(true);
    now = expired.expiresAt;
    expect(store.admitCommit(expired)).toBe(false);
    expect(expired.status).toBe("error");
    expect(expired.signal.aborted).toBe(true);

    const canceled = activate(store, "owner", "google", "canceled-before-commit");
    expect(store.claim(canceled)).toBe(true);
    expect(store.cancel(canceled.sessionId, "owner")).toBe(true);
    expect(store.admitCommit(canceled)).toBe(false);
    expect(canceled.signal.aborted).toBe(true);
  });

  it("clears admitted commit state on failure and schedules only terminal retention", () => {
    vi.useFakeTimers();
    let now = 3_000;
    const ended: string[] = [];
    try {
      const store = new OAuthSessionStore<SessionData>({
        now: () => now,
        maxPerOwner: 1,
        maxEntries: 1,
        pendingTtlMs: 100,
        terminalTtlMs: 60,
        onEnd: (session, reason) => {
          ended.push(reason);
          session.data.verifier = undefined;
        },
      });
      const session = activate(store, "owner", "devin", "failed-admitted-commit");
      expect(store.claim(session)).toBe(true);
      expect(store.admitCommit(session)).toBe(true);

      now = session.expiresAt;
      vi.advanceTimersByTime(100);
      expect(session.status).toBe("pending");
      expect(vi.getTimerCount()).toBe(0);
      expect(store.fail(session, "Synthetic SQL failure")).toBe(true);
      expect(session.status).toBe("error");
      expect(session.error).toBe("Synthetic SQL failure");
      expect(session.terminalExpiresAt).toBe(now + 60);
      expect(session.data.verifier).toBeUndefined();
      expect(ended).toEqual(["terminal"]);
      expect(() => store.reserve("owner", "replacement", {})).toThrow(OAuthCapacityError);

      now += 59;
      expect(store.get(session.sessionId)?.status).toBe("error");
      now += 1;
      vi.advanceTimersByTime(60);
      expect(store.get(session.sessionId)).toBeUndefined();
      const replacement = store.reserve("owner", "replacement", {});
      expect(store.cancel(replacement.sessionId, "owner")).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("releases device bindings only when an admitted session reaches its terminal result", () => {
    const store = new OAuthSessionStore<SessionData>();
    const session = activate(store, "owner", "cursor", "cursor-session", "cursor-uuid");
    const claim = store.claimDevice("cursor", "cursor-uuid", "owner");
    if (!claim || claim.status !== "claimed") throw new Error("Expected the synthetic cursor session to be claimed");

    expect(store.admitCommit(session)).toBe(true);
    expect(store.claimDevice("cursor", "cursor-uuid", "owner")).toEqual({ status: "busy" });
    expect(store.complete(session, "Synthetic Cursor")).toBe(true);
    expect(store.claimDevice("cursor", "cursor-uuid", "owner")).toBeUndefined();
    expect(store.get(session.sessionId)?.status).toBe("complete");
  });

});

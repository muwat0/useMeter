import { describe, expect, it } from "bun:test";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { StorageVault } from "../src/core/storage/vault";
import { AuthService } from "../src/core/auth/auth";
import type { PasswordResetMail, PasswordResetMailer } from "../src/core/auth/password-reset-mailer";
import { hashSessionToken } from "../src/core/crypto";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import type { GoogleTokenResult } from "../src/core/oauth/google";
import type { UsageReport, User } from "../src/types";
import { createServer, type AppInstance, type ServerOptions } from "../src/server/app";

const PASSWORD = "Long-lived-test-password-2026!";
const NEXT_PASSWORD = "Replacement-test-password-2026!";

interface TestUser {
  user: User;
  token: string;
  cookie: string;
}

interface HarnessOptions {
  mailer?: PasswordResetMailer;
  now?: () => number;
  adapter?: ProviderAdapter;
  serverOptions?: ServerOptions;
}

interface Harness {
  vault: StorageVault;
  auth: AuthService;
  poller: PollerEngine;
  app: AppInstance;
}

interface MailRecorder {
  mailer: PasswordResetMailer;
  sent: PasswordResetMail[];
  next(): Promise<PasswordResetMail>;
}

function healthyReport(credential: Parameters<ProviderAdapter["fetchUsage"]>[0]): UsageReport {
  return {
    ownerId: credential.ownerId,
    provider: credential.provider,
    credentialId: credential.id,
    accountLabel: credential.accountLabel,
    fetchedAt: Date.now(),
    limits: [],
    health: "healthy",
    source: "live",
  };
}

function createProviderAdapter(
  id: string,
  fetchUsage: ProviderAdapter["fetchUsage"] = async credential => healthyReport(credential),
): ProviderAdapter {
  return {
    id,
    supports: provider => provider === id,
    fetchUsage,
  };
}

function createHarness(options: HarnessOptions = {}): Harness {
  const vault = new StorageVault(":memory:");
  const registry = new ProviderRegistry();
  registry.register(options.adapter ?? createProviderAdapter("account-lifecycle-test-provider"));
  const poller = new PollerEngine(vault, registry, {
    minProviderIntervalMs: 0,
    pollTimeoutMs: 2_000,
  });
  const auth = new AuthService(vault, {
    ...(options.mailer ? { passwordResetMailer: options.mailer } : {}),
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  const app = createServer(vault, poller, registry, auth, options.serverOptions);
  return { vault, auth, poller, app };
}

async function closeHarness(harness: Harness): Promise<void> {
  harness.poller.stop();
  await harness.auth.stopPasswordRecovery();
  harness.vault.close();
}

async function registerUser(auth: AuthService, email: string, password = PASSWORD): Promise<TestUser> {
  const result = await auth.register(email, password);
  if (!result.success) throw new Error("Test user registration failed");
  return {
    user: result.data.user,
    token: result.data.token,
    cookie: `usage_session=${encodeURIComponent(result.data.token)}`,
  };
}

function createMailRecorder(send?: PasswordResetMailer["send"]): MailRecorder {
  const sent: PasswordResetMail[] = [];
  const queued: PasswordResetMail[] = [];
  const waiters: Array<(mail: PasswordResetMail) => void> = [];
  return {
    sent,
    mailer: {
      send(mail, signal) {
        sent.push(mail);
        const waiter = waiters.shift();
        if (waiter) waiter(mail);
        else queued.push(mail);
        return send ? send(mail, signal) : Promise.resolve();
      },
    },
    next() {
      const mail = queued.shift();
      if (mail) return Promise.resolve(mail);
      const next = Promise.withResolvers<PasswordResetMail>();
      waiters.push(next.resolve);
      return next.promise;
    },
  };
}

function eventLoopTurn(): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setImmediate(resolve);
  return promise;
}


function deferred(): { promise: Promise<void>; resolve(): void } {
  const { promise, resolve } = Promise.withResolvers<void>();
  return { promise, resolve };
}

function gatePasswordHash(target: string) {
  const original = Bun.password.hash;
  const started = deferred();
  const release = deferred();
  Bun.password.hash = async (password, options) => {
    if (password === target) {
      started.resolve();
      await release.promise;
    }
    return original(password, options);
  };
  return {
    started: started.promise,
    release: () => release.resolve(),
    restore: () => { Bun.password.hash = original; },
  };
}

function gatePasswordVerify(target: string) {
  const original = Bun.password.verify;
  const started = deferred();
  const release = deferred();
  Bun.password.verify = async (password, hash) => {
    if (password === target) {
      started.resolve();
      await release.promise;
    }
    return original(password, hash);
  };
  return {
    started: started.promise,
    release: () => release.resolve(),
    restore: () => { Bun.password.verify = original; },
  };
}

function accountBody(password: string): string {
  return JSON.stringify({ password });
}

function resetBody(token: string, newPassword: string): string {
  return JSON.stringify({ token, newPassword });
}

const GOOGLE_ENV_KEYS = [
  "NODE_ENV",
  "USAGE_MASTER_KEY",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GOOGLE_OAUTH_REDIRECT_URI",
] as const;

function snapshotGoogleEnv(): Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>> {
  const values: Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>> = {};
  for (const key of GOOGLE_ENV_KEYS) values[key] = process.env[key];
  return values;
}

function restoreGoogleEnv(values: Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>>): void {
  for (const key of GOOGLE_ENV_KEYS) {
    const value = values[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function configureEmbeddedGoogleClient(): void {
  process.env["NODE_ENV"] = "production";
  process.env["USAGE_MASTER_KEY"] = "account-lifecycle-test-master-key";
  process.env["GOOGLE_OAUTH_CLIENT_ID"] = "";
  process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "";
  process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";
}

describe("account lifecycle backend behavior", () => {
  it("changes a password with the shared Unicode policy and revokes only other sessions and reset tokens", async () => {
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer });
    try {
      const account = await registerUser(harness.auth, "password-change@example.test", "😀".repeat(64));
      const otherSession = await harness.auth.login(account.user.email, "😀".repeat(64));
      expect(otherSession.success).toBe(true);
      if (!otherSession.success) return;
      const originalVerify = Bun.password.verify;
      let verifyCalls = 0;
      Bun.password.verify = async (password, hash) => {
        verifyCalls++;
        return originalVerify(password, hash);
      };
      try {
        const rejectedOrigin = await harness.app.request("http://localhost/api/auth/password/change", {
          method: "POST",
          headers: {
            Cookie: account.cookie,
            Origin: "https://attacker.example",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ currentPassword: "😀".repeat(64), newPassword: NEXT_PASSWORD }),
        });
        expect(rejectedOrigin.status).toBe(403);
        expect(verifyCalls).toBe(0);
      } finally {
        Bun.password.verify = originalVerify;
      }

      const wrong = await harness.app.request("/api/auth/password/change", {
        method: "POST",
        headers: { Cookie: account.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: "Incorrect-password-123!", newPassword: NEXT_PASSWORD }),
      });
      expect(wrong.status).toBe(401);
      expect((await wrong.json() as { errorCode: string }).errorCode).toBe("INVALID_CREDENTIALS");
      expect((await harness.auth.authenticate(account.token)).success).toBe(true);
      expect((await harness.auth.authenticate(otherSession.data.token)).success).toBe(true);
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const resetMail = await recorder.next();

      const changed = await harness.app.request("/api/auth/password/change", {
        method: "POST",
        headers: { Cookie: account.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: "😀".repeat(64), newPassword: "😀".repeat(12) }),
      });
      expect(changed.status).toBe(200);
      const invalidatedReset = await harness.auth.confirmPasswordReset(
        resetMail.token,
        "A-different-valid-password-2026!",
      );
      expect(invalidatedReset.success).toBe(false);
      if (!invalidatedReset.success) expect(invalidatedReset.error).toBe("INVALID_RESET_TOKEN");
      expect((await harness.auth.authenticate(account.token)).success).toBe(true);
      expect((await harness.auth.authenticate(otherSession.data.token)).success).toBe(false);
      expect((await harness.auth.login(account.user.email, "😀".repeat(12))).success).toBe(true);

      const tooManyUtf8Bytes = await harness.app.request("/api/auth/password/change", {
        method: "POST",
        headers: { Cookie: account.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: "😀".repeat(12), newPassword: "😀".repeat(65) }),
      });
      expect(tooManyUtf8Bytes.status).toBe(400);
      expect((await tooManyUtf8Bytes.json() as { errorCode: string }).errorCode).toBe("WEAK_PASSWORD");

      let currentPassword = "😀".repeat(12);
      let rateLimited: Response | undefined;
      for (let attempt = 0; attempt < 16; attempt++) {
        const nextPassword = `Rate-limit-rotation-${attempt}-2026!`;
        const response = await harness.app.request("/api/auth/password/change", {
          method: "POST",
          headers: { Cookie: account.cookie, "Content-Type": "application/json" },
          body: JSON.stringify({ currentPassword, newPassword: nextPassword }),
        });
        if (response.status === 429) {
          rateLimited = response;
          break;
        }
        expect(response.status).toBe(200);
        currentPassword = nextPassword;
      }
      if (!rateLimited) throw new Error("Password change requests did not reach the configured rate limit");
      expect((await rateLimited.json() as { errorCode: string }).errorCode).toBe("RATE_LIMITED");
      expect(rateLimited.headers.get("Retry-After")).not.toBeNull();

      const codeUnitAccount = await registerUser(harness.auth, "password-codeunit-bound@example.test");
      const tooManyCodeUnits = await harness.app.request("/api/auth/password/change", {
        method: "POST",
        headers: { Cookie: codeUnitAccount.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: PASSWORD, newPassword: "a".repeat(257) }),
      });
      expect(tooManyCodeUnits.status).toBe(400);
      expect((await tooManyCodeUnits.json() as { errorCode: string }).errorCode).toBe("WEAK_PASSWORD");
      expect((await harness.auth.authenticate(account.token)).success).toBe(true);
    } finally {
      await closeHarness(harness);
    }
  });

  it("rotates, expires, consumes, and replays only the latest hashed reset token", async () => {
    let now = 50_000;
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer, now: () => now });
    try {
      const account = await registerUser(harness.auth, "reset-token@example.test");
      const secondSession = await harness.auth.login(account.user.email, PASSWORD);
      expect(secondSession.success).toBe(true);
      if (!secondSession.success) return;
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const first = await recorder.next();
      expect(harness.vault.getPasswordResetContext(hashSessionToken(first.token), now)).not.toBeNull();
      expect(harness.vault.getPasswordResetContext(first.token, now)).toBeNull();

      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const rotated = await recorder.next();
      expect(rotated.token).not.toBe(first.token);
      expect(harness.vault.getPasswordResetContext(hashSessionToken(first.token), now)).toBeNull();
      expect(harness.vault.getPasswordResetContext(hashSessionToken(rotated.token), now)).not.toBeNull();

      now += 15 * 60 * 1_000 + 1;
      const expired = await harness.auth.confirmPasswordReset(rotated.token, NEXT_PASSWORD);
      expect(expired.success).toBe(false);
      if (!expired.success) expect(expired.error).toBe("INVALID_RESET_TOKEN");
      expect((await harness.auth.authenticate(account.token)).success).toBe(true);

      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const current = await recorder.next();
      const reset = await harness.auth.confirmPasswordReset(current.token, NEXT_PASSWORD);
      expect((await harness.auth.authenticate(secondSession.data.token)).success).toBe(false);
      expect(reset.success).toBe(true);
      expect((await harness.auth.authenticate(account.token)).success).toBe(false);
      const replay = await harness.auth.confirmPasswordReset(current.token, "Another-valid-password-2026!");
      expect(replay.success).toBe(false);
      if (!replay.success) expect(replay.error).toBe("INVALID_RESET_TOKEN");
      expect((await harness.auth.login(account.user.email, NEXT_PASSWORD)).success).toBe(true);
    } finally {
      await closeHarness(harness);
    }
  });

  it("rechecks reset-token expiry after password hashing before consumption", async () => {
    let now = 90_000;
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer, now: () => now });
    const gate = gatePasswordHash(NEXT_PASSWORD);
    try {
      const account = await registerUser(harness.auth, "reset-expiry-race@example.test");
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const mail = await recorder.next();
      const confirmation = harness.auth.confirmPasswordReset(mail.token, NEXT_PASSWORD);
      await gate.started;
      now += 15 * 60 * 1_000 + 1;
      gate.release();

      const result = await confirmation;
      expect(result.success).toBe(false);
      if (!result.success) expect(result.error).toBe("INVALID_RESET_TOKEN");
      expect((await harness.auth.authenticate(account.token)).success).toBe(true);
    } finally {
      gate.release();
      gate.restore();
      await closeHarness(harness);
    }
  });

  it("keeps known and unknown recovery responses identical when delivery fails", async () => {
    const attempted: PasswordResetMail[] = [];
    const mailer: PasswordResetMailer = {
      send(mail) {
        attempted.push(mail);
        return Promise.reject(new Error("synthetic delivery failure"));
      },
    };
    const harness = createHarness({ mailer });
    try {
      const account = await registerUser(harness.auth, "known-recovery@example.test");
      const request = (email: string) => harness.app.request("/api/auth/password/reset-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const knownResponse = await request(account.user.email);
      const unknownResponse = await request("unknown-recovery@example.test");
      expect(knownResponse.status).toBe(202);
      expect(unknownResponse.status).toBe(202);
      expect(await knownResponse.json()).toEqual(await unknownResponse.json());
      await eventLoopTurn();
      expect(attempted).toHaveLength(1);
      expect(attempted[0]?.recipient).toBe(account.user.email);
    } finally {
      await closeHarness(harness);
    }
  });

  it("returns a global unavailable response without configured recovery mail", async () => {
    const harness = createHarness();
    try {
      const account = await registerUser(harness.auth, "recovery-unconfigured@example.test");
      const request = (email: string) => harness.app.request("/api/auth/password/reset-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const known = await request(account.user.email);
      const unknown = await request("unconfigured-unknown@example.test");
      expect(known.status).toBe(503);
      expect(unknown.status).toBe(503);
      expect(await known.json()).toEqual(await unknown.json());
    } finally {
      await closeHarness(harness);
    }
  });

  it("does not await a hanging mail sink and still accepts unknown addresses uniformly", async () => {
    const started = deferred();
    const attempted: PasswordResetMail[] = [];
    const mailer: PasswordResetMailer = {
      send(mail) {
        attempted.push(mail);
        started.resolve();
        return deferred().promise;
      },
    };
    const harness = createHarness({ mailer });
    try {
      const account = await registerUser(harness.auth, "hanging-recovery@example.test");
      const request = (email: string) => harness.app.request("/api/auth/password/reset-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const knownResponse = await request(account.user.email);
      expect(knownResponse.status).toBe(202);
      await started.promise;
      const unknownResponse = await request("no-account@example.test");
      expect(unknownResponse.status).toBe(202);
      expect(await knownResponse.json()).toEqual(await unknownResponse.json());
      await eventLoopTurn();
      await harness.auth.stopPasswordRecovery();
      expect(attempted).toHaveLength(1);
    } finally {
      await closeHarness(harness);
    }
  });

  it("allows an account-A reset token with a B cookie without revoking or clearing B", async () => {
    const recorder = createMailRecorder();
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const adapter = createProviderAdapter("account-lifecycle-test-provider", async credential => {
      providerStarted.resolve();
      await providerGate.promise;
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const harness = createHarness({ mailer: recorder.mailer, adapter });
    try {
      const first = await registerUser(harness.auth, "reset-owner-a@example.test");
      const second = await registerUser(harness.auth, "reset-cookie-b@example.test");
      const foreignCredential = harness.vault.saveCredential(second.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "B-owned credential",
        credentialType: "api_key",
        secret: "foreign-owner-secret",
      });
      harness.vault.saveUsageSnapshot(second.user.id, {
        provider: foreignCredential.provider,
        credentialId: foreignCredential.id,
        accountLabel: foreignCredential.accountLabel,
        fetchedAt: Date.now(),
        limits: [],
      });
      const staged = harness.app.request("/api/credentials", {
        method: "POST",
        headers: { Cookie: second.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "account-lifecycle-test-provider",
          accountLabel: "B staged after A reset",
          credentialType: "api_key",
          secret: "b-session-secret",
        }),
      });
      await providerStarted.promise;

      const requested = await harness.app.request("/api/auth/password/reset-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: first.user.email }),
      });
      expect(requested.status).toBe(202);
      const resetMail = await recorder.next();
      const reset = await harness.app.request("/api/auth/password/reset-confirm", {
        method: "POST",
        headers: { Cookie: second.cookie, "Content-Type": "application/json" },
        body: resetBody(resetMail.token, NEXT_PASSWORD),
      });
      expect(reset.status).toBe(200);
      expect(await reset.json()).toEqual({ success: true });
      expect(reset.headers.get("Set-Cookie")).toBeNull();
      expect((await harness.auth.authenticate(first.token)).success).toBe(false);
      providerGate.resolve();
      const stagedResponse = await staged;
      await providerReturned.promise;
      await eventLoopTurn();
      expect(stagedResponse.status).toBe(200);
      expect((await harness.auth.authenticate(second.token)).success).toBe(true);
      expect(harness.vault.getCredential(second.user.id, foreignCredential.id)).not.toBeNull();
      expect(harness.vault.getLatestUsage(second.user.id)).toHaveLength(2);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
    }
  });

  it("still consumes an issued token after the mail transport is stopped", async () => {
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer });
    try {
      const account = await registerUser(harness.auth, "transport-stopped@example.test");
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const mail = await recorder.next();
      await harness.auth.stopPasswordRecovery();
      expect(harness.auth.isPasswordRecoveryConfigured()).toBe(false);

      const reset = await harness.app.request("/api/auth/password/reset-confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: resetBody(mail.token, NEXT_PASSWORD),
      });
      expect(reset.status).toBe(200);
      expect((await harness.auth.login(account.user.email, NEXT_PASSWORD)).success).toBe(true);
    } finally {
      await closeHarness(harness);
    }
  });

  it("does not create a stale-password login session after reset commits during verification", async () => {
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer });
    const gate = gatePasswordVerify(PASSWORD);
    try {
      const account = await registerUser(harness.auth, "login-reset-race@example.test");
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const mail = await recorder.next();
      const sessionsBefore = harness.vault.getSystemStatsAdmin(false).activeSessions;

      const staleLogin = harness.auth.login(account.user.email, PASSWORD);
      await gate.started;
      const reset = await harness.auth.confirmPasswordReset(mail.token, NEXT_PASSWORD);
      expect(reset.success).toBe(true);
      gate.release();

      const login = await staleLogin;
      expect(login.success).toBe(false);
      expect(harness.vault.getSystemStatsAdmin(false).activeSessions).toBe(sessionsBefore - 1);
    } finally {
      gate.release();
      gate.restore();
      await closeHarness(harness);
    }
  });

  it("rejects a password change whose hash finishes after reset or logout", async () => {
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer });
    const gate = gatePasswordHash("Change-that-loses-the-CAS-2026!");
    try {
      const account = await registerUser(harness.auth, "change-reset-race@example.test");
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const mail = await recorder.next();
      const changePromise = harness.auth.changePassword(
        account.user.id,
        account.token,
        PASSWORD,
        "Change-that-loses-the-CAS-2026!",
      );
      await gate.started;
      const reset = await harness.auth.confirmPasswordReset(mail.token, NEXT_PASSWORD);
      expect(reset.success).toBe(true);
      gate.release();
      const change = await changePromise;
      expect(change.success).toBe(false);
      if (!change.success) expect(change.error).toBe("UNAUTHENTICATED");
      expect((await harness.auth.authenticate(account.token)).success).toBe(false);
    } finally {
      gate.release();
      gate.restore();
      await closeHarness(harness);
    }
  });

  it("rejects a password change when logout wins while the new hash is pending", async () => {
    const harness = createHarness();
    const gate = gatePasswordHash("Change-that-loses-logout-2026!");
    try {
      const account = await registerUser(harness.auth, "change-logout-race@example.test");
      const changePromise = harness.auth.changePassword(
        account.user.id,
        account.token,
        PASSWORD,
        "Change-that-loses-logout-2026!",
      );
      await gate.started;
      await harness.auth.logout(account.token);
      gate.release();

      const change = await changePromise;
      expect(change.success).toBe(false);
      if (!change.success) expect(change.error).toBe("UNAUTHENTICATED");
      expect((await harness.auth.login(account.user.email, PASSWORD)).success).toBe(true);
      expect((await harness.auth.login(account.user.email, "Change-that-loses-logout-2026!")).success).toBe(false);
    } finally {
      gate.release();
      gate.restore();
      await closeHarness(harness);
    }
  });

  it("rejects a self-delete whose password verification finishes after recovery reset", async () => {
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer });
    const gate = gatePasswordVerify(PASSWORD);
    try {
      const account = await registerUser(harness.auth, "delete-reset-race@example.test");
      expect(harness.auth.requestPasswordReset(account.user.email).success).toBe(true);
      const mail = await recorder.next();
      const deletion = harness.auth.deleteAccount(account.user.id, account.token, PASSWORD);
      await gate.started;
      const reset = await harness.auth.confirmPasswordReset(mail.token, NEXT_PASSWORD);
      expect(reset.success).toBe(true);
      gate.release();

      const result = await deletion;
      expect(result.success).toBe(false);
      if (!result.success) expect(result.error).toBe("UNAUTHENTICATED");
      expect(harness.vault.getUserById(account.user.id)).not.toBeNull();
      expect((await harness.auth.authenticate(account.token)).success).toBe(false);
    } finally {
      gate.release();
      gate.restore();
      await closeHarness(harness);
    }
  });

  it("binds password change and account deletion to the target user's active session", async () => {
    const harness = createHarness();
    try {
      const first = await registerUser(harness.auth, "cross-owner-target@example.test");
      const second = await registerUser(harness.auth, "cross-owner-session@example.test");
      const changed = await harness.auth.changePassword(first.user.id, second.token, PASSWORD, NEXT_PASSWORD);
      expect(changed.success).toBe(false);
      if (!changed.success) expect(changed.error).toBe("UNAUTHENTICATED");
      const deleted = await harness.auth.deleteAccount(first.user.id, second.token, PASSWORD);
      expect(deleted.success).toBe(false);
      if (!deleted.success) expect(deleted.error).toBe("UNAUTHENTICATED");
      expect(harness.vault.getUserById(first.user.id)).not.toBeNull();
      expect((await harness.auth.authenticate(second.token)).success).toBe(true);
    } finally {
      await closeHarness(harness);
    }
  });

  it("rejects a self-delete after its verified session logs out while Argon2 verification is pending", async () => {
    const harness = createHarness();
    const gate = gatePasswordVerify(PASSWORD);
    try {
      const account = await registerUser(harness.auth, "delete-logout-race@example.test");
      const deletion = harness.auth.deleteAccount(account.user.id, account.token, PASSWORD);
      await gate.started;
      await harness.auth.logout(account.token);
      gate.release();

      const result = await deletion;
      expect(result.success).toBe(false);
      if (!result.success) expect(result.error).toBe("UNAUTHENTICATED");
      expect(harness.vault.getUserById(account.user.id)).not.toBeNull();
    } finally {
      gate.release();
      gate.restore();
      await closeHarness(harness);
    }
  });

  it("preserves last-admin and owner-cascade rules while cancelling staged owner work", async () => {
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const recorder = createMailRecorder();
    const adapter = createProviderAdapter("account-lifecycle-test-provider", async credential => {
      providerStarted.resolve();
      await providerGate.promise;
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const harness = createHarness({ adapter, mailer: recorder.mailer });
    try {
      const owner = await registerUser(harness.auth, "deleting-admin@example.test");
      const foreign = await registerUser(harness.auth, "remaining-admin@example.test");
      const ownerCredential = harness.vault.saveCredential(owner.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Owned history",
        credentialType: "api_key",
        secret: "owned-secret",
      });
      const foreignCredential = harness.vault.saveCredential(foreign.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Foreign history",
        credentialType: "api_key",
        secret: "foreign-secret",
      });
      for (const [user, credential] of [[owner.user, ownerCredential], [foreign.user, foreignCredential]] as const) {
        harness.vault.saveUsageSnapshot(user.id, {
          provider: credential.provider,
          credentialId: credential.id,
          accountLabel: credential.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
        });
      }
      const invitation = await harness.auth.createInvitation(owner.user.id, "invited-before-delete@example.test");
      expect(invitation.success).toBe(true);
      if (!invitation.success) return;
      expect(harness.auth.requestPasswordReset(owner.user.email).success).toBe(true);
      const resetMail = await recorder.next();
      expect(harness.vault.getPasswordResetContext(hashSessionToken(resetMail.token))).not.toBeNull();

      const wrongDelete = await harness.app.request("/api/auth/account", {
        method: "DELETE",
        headers: { Cookie: owner.cookie, "Content-Type": "application/json" },
        body: accountBody("Incorrect-delete-password-2026!"),
      });
      expect(wrongDelete.status).toBe(401);
      expect((await wrongDelete.json() as { errorCode: string }).errorCode).toBe("INVALID_CREDENTIALS");
      const lastAdmin = await harness.app.request("/api/auth/account", {
        method: "DELETE",
        headers: { Cookie: owner.cookie, "Content-Type": "application/json" },
        body: accountBody(PASSWORD),
      });
      expect(lastAdmin.status).toBe(409);
      expect((await lastAdmin.json() as { errorCode: string }).errorCode).toBe("LAST_ADMIN");
      expect(harness.vault.getUserById(owner.user.id)).not.toBeNull();
      expect((await harness.auth.authenticate(owner.token)).success).toBe(true);
      expect(harness.vault.updateUserRoleAdmin(owner.user.id, foreign.user.id, "admin").success).toBe(true);

      const stagedWrite = harness.app.request("/api/credentials", {
        method: "POST",
        headers: { Cookie: owner.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "account-lifecycle-test-provider",
          accountLabel: "Late staged credential",
          credentialType: "api_key",
          secret: "must-not-persist",
        }),
      });
      await providerStarted.promise;
      const deleted = await harness.app.request("/api/auth/account", {
        method: "DELETE",
        headers: { Cookie: owner.cookie, "Content-Type": "application/json" },
        body: accountBody(PASSWORD),
      });
      expect(deleted.status).toBe(200);
      expect(deleted.headers.get("Set-Cookie")).toContain("Max-Age=0");
      await stagedWrite;
      providerGate.resolve();
      await providerReturned.promise;
      await eventLoopTurn();

      expect(harness.vault.getUserById(owner.user.id)).toBeNull();
      expect(harness.vault.getCredential(owner.user.id, ownerCredential.id)).toBeNull();
      expect(harness.vault.getLatestUsage(owner.user.id)).toHaveLength(0);
      expect((await harness.auth.authenticate(owner.token)).success).toBe(false);
      expect(harness.vault.getInvitationByTokenHash(hashSessionToken(invitation.data.token))).toBeNull();
      expect(harness.vault.getPasswordResetContext(hashSessionToken(resetMail.token))).toBeNull();
      expect(harness.vault.getCredential(foreign.user.id, foreignCredential.id)).not.toBeNull();
      expect(harness.vault.getLatestUsage(foreign.user.id)).toHaveLength(1);
      expect((await harness.auth.authenticate(foreign.token)).success).toBe(true);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
    }
  });

  it("denies a late manual credential write after the originating request logs out", async () => {
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const adapter = createProviderAdapter("account-lifecycle-test-provider", async credential => {
      providerStarted.resolve();
      await providerGate.promise;
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const harness = createHarness({ adapter });
    try {
      const account = await registerUser(harness.auth, "manual-write-revocation@example.test");
      const lateWrite = harness.app.request("/api/credentials", {
        method: "POST",
        headers: { Cookie: account.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "account-lifecycle-test-provider",
          accountLabel: "Revoked request",
          credentialType: "api_key",
          secret: "must-not-persist",
        }),
      });
      await providerStarted.promise;
      const logout = await harness.app.request("/api/auth/logout", {
        method: "POST",
        headers: { Cookie: account.cookie },
      });
      expect(logout.status).toBe(200);
      providerGate.resolve();
      const writeResponse = await lateWrite;
      await providerReturned.promise;
      expect(writeResponse.status).toBe(400);
      expect(harness.vault.listCredentials(account.user.id)).toHaveLength(0);
      expect(harness.vault.getLatestUsage(account.user.id)).toHaveLength(0);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
    }
  });

  it("does not refresh tokens or write poll snapshots after the polling session logs out", async () => {
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const adapter = createProviderAdapter("account-lifecycle-test-provider", async (credential, context) => {
      providerStarted.resolve();
      await providerGate.promise;
      context?.onTokenRefresh?.("late-refreshed-secret");
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const harness = createHarness({ adapter });
    try {
      const account = await registerUser(harness.auth, "manual-poll-revocation@example.test");
      const credential = harness.vault.saveCredential(account.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Existing poll account",
        credentialType: "api_key",
        secret: "original-provider-secret",
      });
      const latePoll = harness.app.request("/api/poll", {
        method: "POST",
        headers: { Cookie: account.cookie },
      });
      await providerStarted.promise;

      const logout = await harness.app.request("/api/auth/logout", {
        method: "POST",
        headers: { Cookie: account.cookie },
      });
      expect(logout.status).toBe(200);
      providerGate.resolve();
      await latePoll;
      await providerReturned.promise;
      await eventLoopTurn();

      expect(harness.vault.getCredential(account.user.id, credential.id)?.secret).toBe("original-provider-secret");
      expect(harness.vault.getLatestUsage(account.user.id)).toHaveLength(0);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
    }
  });

  it("cancels an active owner poll before account cascade without changing another owner", async () => {
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const adapter = createProviderAdapter("account-lifecycle-test-provider", async (credential, context) => {
      providerStarted.resolve();
      await providerGate.promise;
      context?.onTokenRefresh?.("late-poll-refresh");
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const harness = createHarness({ adapter });
    try {
      const administrator = await registerUser(harness.auth, "poll-cascade-admin@example.test");
      const owner = await registerUser(harness.auth, "poll-cascade-owner@example.test");
      const ownerCredential = harness.vault.saveCredential(owner.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Poll owner credential",
        credentialType: "oauth",
        secret: "before-account-delete",
      });
      const adminCredential = harness.vault.saveCredential(administrator.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Administrator credential",
        credentialType: "api_key",
        secret: "retained-admin-key",
      });
      harness.vault.saveUsageSnapshot(administrator.user.id, {
        provider: adminCredential.provider,
        credentialId: adminCredential.id,
        accountLabel: adminCredential.accountLabel,
        fetchedAt: Date.now(),
        limits: [],
      });

      const poll = harness.app.request(`/api/credentials/${encodeURIComponent(ownerCredential.id)}/poll`, {
        method: "POST",
        headers: { Cookie: owner.cookie },
      });
      await providerStarted.promise;
      const deleted = await harness.app.request("/api/auth/account", {
        method: "DELETE",
        headers: { Cookie: owner.cookie, "Content-Type": "application/json" },
        body: accountBody(PASSWORD),
      });
      expect(deleted.status).toBe(200);
      providerGate.resolve();
      await poll;
      await providerReturned.promise;
      await eventLoopTurn();

      expect(harness.vault.getUserById(owner.user.id)).toBeNull();
      expect(harness.vault.getCredential(owner.user.id, ownerCredential.id)).toBeNull();
      expect(harness.vault.getLatestUsage(owner.user.id)).toHaveLength(0);
      expect(harness.vault.getCredential(administrator.user.id, adminCredential.id)?.secret).toBe("retained-admin-key");
      expect(harness.vault.getLatestUsage(administrator.user.id)).toHaveLength(1);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
    }
  });

  it("admin deletion cancels the target owner's staged work without affecting the administrator", async () => {
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const adapter = createProviderAdapter("account-lifecycle-test-provider", async credential => {
      providerStarted.resolve();
      await providerGate.promise;
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const harness = createHarness({ adapter });
    try {
      const target = await registerUser(harness.auth, "admin-delete-target@example.test");
      const administrator = await registerUser(harness.auth, "admin-delete-operator@example.test");
      expect(harness.vault.updateUserRoleAdmin(target.user.id, administrator.user.id, "admin").success).toBe(true);
      expect(harness.vault.updateUserRoleAdmin(administrator.user.id, target.user.id, "user").success).toBe(true);
      const retained = harness.vault.saveCredential(administrator.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Administrator-owned data",
        credentialType: "api_key",
        secret: "administrator-secret",
      });

      const lateWrite = harness.app.request("/api/credentials", {
        method: "POST",
        headers: { Cookie: target.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "account-lifecycle-test-provider",
          accountLabel: "Admin-deleted staged write",
          credentialType: "api_key",
          secret: "must-not-persist",
        }),
      });
      await providerStarted.promise;
      const deletion = await harness.app.request(`/api/admin/users/${encodeURIComponent(target.user.id)}`, {
        method: "DELETE",
        headers: { Cookie: administrator.cookie },
      });
      expect(deletion.status).toBe(200);
      const lateResponse = await lateWrite;
      expect(lateResponse.status).toBe(400);
      providerGate.resolve();
      await providerReturned.promise;
      await eventLoopTurn();

      expect(harness.vault.getUserById(target.user.id)).toBeNull();
      expect(harness.vault.listCredentials(target.user.id)).toHaveLength(0);
      expect(harness.vault.getCredential(administrator.user.id, retained.id)).not.toBeNull();
      expect((await harness.auth.authenticate(administrator.token)).success).toBe(true);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
    }
  });

  it("denies an OAuth credential that returns after password change revoked its owner flow", async () => {
    const env = snapshotGoogleEnv();
    configureEmbeddedGoogleClient();
    const providerStarted = deferred();
    const providerReturned = deferred();
    const providerGate = deferred();
    const adapter = createProviderAdapter("antigravity", async credential => {
      providerStarted.resolve();
      await providerGate.promise;
      providerReturned.resolve();
      return healthyReport(credential);
    });
    const options: ServerOptions = {
      googleOAuthExchange: async (): Promise<GoogleTokenResult> => ({
        accessToken: "synthetic-oauth-access-token",
        refreshToken: "synthetic-oauth-refresh-token",
        email: "oauth-account@example.test",
      }),
    };
    const harness = createHarness({ adapter, serverOptions: options });
    try {
      const account = await registerUser(harness.auth, "oauth-revocation@example.test");
      const initiation = await harness.app.request("/api/oauth/google/initiate", {
        method: "POST",
        headers: { Cookie: account.cookie },
      });
      expect(initiation.status).toBe(200);
      const initiationBody = await initiation.json() as { data: { sessionId: string } };
      const callbackInput = new URL("http://127.0.0.1:51121/oauth-callback");
      callbackInput.searchParams.set("code", "synthetic-oauth-code");
      callbackInput.searchParams.set("state", initiationBody.data.sessionId);

      const completion = harness.app.request("/api/oauth/manual", {
        method: "POST",
        headers: { Cookie: account.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: initiationBody.data.sessionId, callbackInput: callbackInput.toString() }),
      });
      await providerStarted.promise;
      const changed = await harness.app.request("/api/auth/password/change", {
        method: "POST",
        headers: { Cookie: account.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: PASSWORD, newPassword: NEXT_PASSWORD }),
      });
      expect(changed.status).toBe(200);
      const completionResponse = await completion;
      expect(completionResponse.status).toBe(404);
      providerGate.resolve();
      await providerReturned.promise;
      await eventLoopTurn();
      expect(harness.vault.listCredentials(account.user.id)).toHaveLength(0);
      expect(harness.vault.getLatestUsage(account.user.id)).toHaveLength(0);
    } finally {
      providerGate.resolve();
      await closeHarness(harness);
      restoreGoogleEnv(env);
    }
  });

  it("runs the standalone Vault, Auth, Hono, mail, and fake-provider lifecycle smoke", async () => {
    const recorder = createMailRecorder();
    const harness = createHarness({ mailer: recorder.mailer });
    try {
      const owner = await registerUser(harness.auth, "lifecycle-smoke-owner@example.test");
      const remainingAdmin = await registerUser(harness.auth, "lifecycle-smoke-admin@example.test");
      expect(harness.vault.updateUserRoleAdmin(owner.user.id, remainingAdmin.user.id, "admin").success).toBe(true);

      const request = await harness.app.request("/api/auth/password/reset-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: owner.user.email }),
      });
      expect(request.status).toBe(202);
      expect(await request.json()).toEqual({ success: true });
      const mail = await recorder.next();
      const confirmed = await harness.app.request("/api/auth/password/reset-confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: resetBody(mail.token, NEXT_PASSWORD),
      });
      expect(confirmed.status).toBe(200);
      expect(confirmed.headers.get("Set-Cookie")).toBeNull();
      expect((await harness.auth.authenticate(owner.token)).success).toBe(false);

      const login = await harness.app.request("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: owner.user.email, password: NEXT_PASSWORD }),
      });
      expect(login.status).toBe(200);
      const loginBody = await login.json() as { success: boolean };
      expect(loginBody.success).toBe(true);
      const loginCookie = login.headers.get("Set-Cookie");
      expect(loginCookie).not.toBeNull();
      const loginToken = decodeURIComponent(loginCookie!.split(";")[0]!.slice("usage_session=".length));

      const saved = await harness.app.request("/api/credentials", {
        method: "POST",
        headers: { Cookie: loginCookie!.split(";")[0]!, "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "account-lifecycle-test-provider",
          accountLabel: "Smoke provider",
          credentialType: "api_key",
          secret: "synthetic-provider-secret",
        }),
      });
      expect(saved.status).toBe(200);
      expect(harness.vault.listCredentials(owner.user.id)).toHaveLength(1);
      expect(harness.vault.getLatestUsage(owner.user.id)).toHaveLength(1);

      const foreign = harness.vault.saveCredential(remainingAdmin.user.id, {
        provider: "account-lifecycle-test-provider",
        accountLabel: "Retained foreign data",
        credentialType: "api_key",
        secret: "foreign-provider-secret",
      });
      harness.vault.saveUsageSnapshot(remainingAdmin.user.id, {
        provider: foreign.provider,
        credentialId: foreign.id,
        accountLabel: foreign.accountLabel,
        fetchedAt: Date.now(),
        limits: [],
      });
      const deleted = await harness.app.request("/api/auth/account", {
        method: "DELETE",
        headers: { Cookie: loginCookie!.split(";")[0]!, "Content-Type": "application/json" },
        body: accountBody(NEXT_PASSWORD),
      });
      expect(deleted.status).toBe(200);
      expect(harness.vault.getUserById(owner.user.id)).toBeNull();
      expect((await harness.auth.authenticate(loginToken)).success).toBe(false);
      expect(harness.vault.getCredential(remainingAdmin.user.id, foreign.id)).not.toBeNull();
      expect(harness.vault.getLatestUsage(remainingAdmin.user.id)).toHaveLength(1);
    } finally {
      await closeHarness(harness);
    }
  });
});

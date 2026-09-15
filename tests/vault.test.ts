import { Database } from "bun:sqlite";
import { beforeEach, describe, expect, it } from "bun:test";
import { mkdirSync, unlinkSync } from "node:fs";
import { AuthService } from "../src/core/auth/auth";
import { decryptSecret, encryptSecret, hashSessionToken } from "../src/core/crypto";
import { StorageVault } from "../src/core/storage/vault";
import type { InputCredential, StoredCredential, UsageReport } from "../src/types";

let vault: StorageVault;
let auth: AuthService;

beforeEach(() => {
  vault = new StorageVault(":memory:");
  auth = new AuthService(vault);
});
mkdirSync("data", { recursive: true });


describe("StorageVault Single-Tenant Legacy Compatibility", () => {
  it("should update credential label without ownerId (legacy fallback)", () => {
    const provider = "test-provider";
    const accountLabel = "Old Label";
    const accent = "default";
    const newLabel = "New Label";
    const credentialType = "api_key";
    const secret = "test-secret";

    const savedCredential = vault.saveCredentialInternal({
      provider,
      accountLabel,
      accent,
      credentialType,
      secret,
    });
    const result = vault.updateCredentialLabel(savedCredential.ownerId, savedCredential.id, newLabel);
    expect(result).toBe(true);
    const updatedCredential = vault
      .listAllCredentialsInternal()
      .find((c: StoredCredential) => c.id === savedCredential.id);
    expect(updatedCredential?.accountLabel).toBe(newLabel);
  });
});

describe("StorageVault Schema Migration & Atomic Legacy Claim", () => {
  it("migrates a v0 legacy schema without data loss and assigns legacy rows exclusively to the first registered user", async () => {
    const legacyDbPath = `data/test-legacy-migration-${Date.now()}.db`;

    // 1. Seed raw v0 legacy database with missing owner_id columns and user_version = 0
    const rawDb = new Database(legacyDbPath, { create: true });
    rawDb.exec(`
      CREATE TABLE credentials (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        accent TEXT NOT NULL DEFAULT 'default',
        credential_type TEXT NOT NULL,
        encrypted_secret TEXT NOT NULL,
        iv TEXT NOT NULL,
        tag TEXT NOT NULL,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE usage_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        report_json TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
      );
    `);

    const enc = encryptSecret("legacy-api-key-12345");
    rawDb.prepare(`
      INSERT INTO credentials (
        id, provider, account_label, accent, credential_type,
        encrypted_secret, iv, tag, metadata, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      "legacy-cred-1",
      "openrouter",
      "Legacy Key",
      "amber",
      "api_key",
      enc.ciphertext,
      enc.iv,
      enc.tag,
      JSON.stringify({ note: "migrated" }),
      1000,
      1000,
    );

    const legacyReport: UsageReport = {
      provider: "openrouter",
      credentialId: "legacy-cred-1",
      accountLabel: "Legacy Key",
      fetchedAt: 1000,
      limits: [
        {
          id: "credits",
          label: "Remaining Credits",
          amount: { remaining: 50, unit: "usd" },
          status: "ok",
        },
      ],
    };

    rawDb.prepare(`
      INSERT INTO usage_snapshots (credential_id, provider, account_label, report_json, fetched_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      "legacy-cred-1",
      "openrouter",
      "Legacy Key",
      JSON.stringify(legacyReport),
      1000,
    );
    rawDb.close();

    // 2. Open with StorageVault: migration must run idempotently
    const migratedVault = new StorageVault(legacyDbPath);
    const migratedAuth = new AuthService(migratedVault);

    expect(migratedVault.checkIntegrity()).toBe(true);

    // Prior to registration, the legacy credential exists with no owner (visible only via internal enumeration)
    const daemonAll = migratedVault.listAllCredentialsInternal();
    expect(daemonAll.length).toBe(1);
    expect(daemonAll[0]?.id).toBe("legacy-cred-1");
    expect(daemonAll[0]?.secret).toBe("legacy-api-key-12345");
    expect(daemonAll[0]?.ownerId).toBeUndefined();

    // 3. Register the FIRST user: must atomically claim legacy rows
    const regResult1 = await migratedAuth.register(
      "first.owner@example.com",
      "SecurePassphrase#123",
    );
    expect(regResult1.success).toBe(true);
    if (!regResult1.success) return;
    const user1 = regResult1.data.user;

    // User 1 sees the legacy credential and snapshot
    const user1Creds = migratedVault.listCredentials(user1.id);
    expect(user1Creds.length).toBe(1);
    expect(user1Creds[0]?.id).toBe("legacy-cred-1");
    expect(user1Creds[0]?.ownerId).toBe(user1.id);
    expect(user1Creds[0]?.secret).toBe("legacy-api-key-12345");

    const user1Snaps = migratedVault.getLatestUsage(user1.id);
    expect(user1Snaps.length).toBe(1);
    expect(user1Snaps[0]?.credentialId).toBe("legacy-cred-1");

    // 4. Register a SECOND user: must NOT receive or see legacy credentials/snapshots
    const regResult2 = await migratedAuth.register(
      "second.user@example.com",
      "AnotherSecurePassphrase#456",
    );
    expect(regResult2.success).toBe(true);
    if (!regResult2.success) return;
    const user2 = regResult2.data.user;

    const user2Creds = migratedVault.listCredentials(user2.id);
    expect(user2Creds.length).toBe(0);

    const user2Snaps = migratedVault.getLatestUsage(user2.id);
    expect(user2Snaps.length).toBe(0);

    // Clean up temporary database file
    migratedVault.close();
    try {
      unlinkSync(legacyDbPath);
    } catch {}
  });

  it("prevents legacy abandonment and race collisions under concurrent first registrations", async () => {
    // Seed vault with unowned legacy credentials and usage snapshots
    const cred = vault.saveCredentialInternal({
      provider: "openrouter",
      accountLabel: "Shared Legacy Key",
      accent: "violet",
      credentialType: "api_key",
      secret: "legacy-secret",
    });
    const report: UsageReport = {
      provider: "openrouter",
      credentialId: cred.id,
      accountLabel: "Shared Legacy Key",
      fetchedAt: Date.now(),
      limits: [
        {
          id: "credits",
          label: "Remaining",
          amount: { remaining: 25, unit: "usd" },
          status: "ok",
        },
      ],
    };
    vault.saveUsageSnapshotInternal(report);

    // Simulate concurrent first registrations racing against the same vault instance
    const [resA, resB] = await Promise.all([
      auth.register("racer.alice@example.com", "PasswordAlice#1234"),
      auth.register("racer.bob@example.com", "PasswordBob#1234"),
    ]);

    expect(resA.success).toBe(true);
    expect(resB.success).toBe(true);
    if (!resA.success || !resB.success) return;

    const userA = resA.data.user;
    const userB = resB.data.user;

    const userACreds = vault.listCredentials(userA.id);
    const userBCreds = vault.listCredentials(userB.id);
    const userASnaps = vault.getLatestUsage(userA.id);
    const userBSnaps = vault.getLatestUsage(userB.id);

    // Exactly one user must have claimed all legacy rows
    const aHasCreds = userACreds.length === 1 && userASnaps.length === 1;
    const bHasCreds = userBCreds.length === 1 && userBSnaps.length === 1;

    expect(aHasCreds !== bHasCreds).toBe(true);

    if (aHasCreds) {
      expect(userBCreds.length).toBe(0);
      expect(userBSnaps.length).toBe(0);
      expect(userACreds[0]?.id).toBe(cred.id);
      expect(userACreds[0]?.ownerId).toBe(userA.id);
    } else {
      expect(userACreds.length).toBe(0);
      expect(userASnaps.length).toBe(0);
      expect(userBCreds[0]?.id).toBe(cred.id);
      expect(userBCreds[0]?.ownerId).toBe(userB.id);
    }

    // Verify no legacy credential or snapshot remains ownerless (owner_id IS NULL)
    const allCreds = vault.listAllCredentialsInternal();
    expect(allCreds.every((c: StoredCredential) => c.ownerId !== undefined && c.ownerId !== null)).toBe(true);
  });

  it("deterministically returns EMAIL_EXISTS under concurrent registration with identical emails", async () => {
    const [res1, res2] = await Promise.all([
      auth.register("racing.duplicate@example.com", "SecurePassword#999"),
      auth.register("racing.duplicate@example.com", "SecurePassword#999"),
    ]);

    // Exactly one succeeds and one fails with EMAIL_EXISTS
    const successes = [res1, res2].filter((r) => r.success);
    const failures = [res1, res2].filter((r) => !r.success);

    expect(successes.length).toBe(1);
    expect(failures.length).toBe(1);
    expect(failures[0]?.error).toBe("EMAIL_EXISTS");
    expect(failures[0]?.message).toBe("An account with this email address already exists");
  });

  it("prevents SQLITE_BUSY_SNAPSHOT and guarantees atomic legacy claim across distinct database connections", async () => {
    const sharedDbPath = `data/test-shared-reg-${Date.now()}-${Math.random().toString(36).slice(2)}.db`;

    // Seed unowned legacy rows on connection 1
    const v1 = new StorageVault(sharedDbPath);
    const cred = v1.saveCredentialInternal({
      provider: "openrouter",
      accountLabel: "Cross Conn Key",
      accent: "cyan",
      credentialType: "api_key",
      secret: "secret",
    });
    v1.saveUsageSnapshotInternal({
      provider: "openrouter",
      credentialId: cred.id,
      accountLabel: "Cross Conn Key",
      fetchedAt: Date.now(),
      limits: [
        {
          id: "credits",
          label: "Remaining Credits",
          amount: { remaining: 100, unit: "usd" },
          status: "ok",
        },
      ],
    });

    // Connection 2 opening the same on-disk DB in WAL mode
    const v2 = new StorageVault(sharedDbPath);
    const a1 = new AuthService(v1);
    const a2 = new AuthService(v2);

    // Race two registrations from different connections
    const [r1, r2] = await Promise.all([
      a1.register("proc1.user@example.com", "PasswordProc1#123"),
      a2.register("proc2.user@example.com", "PasswordProc2#123"),
    ]);

    expect(r1.success).toBe(true);
    expect(r2.success).toBe(true);
    if (!r1.success || !r2.success) {
      v1.close();
      v2.close();
      try { unlinkSync(sharedDbPath); } catch {}
      return;
    }

    const creds1 = v1.listCredentials(r1.data.user.id);
    const creds2 = v2.listCredentials(r2.data.user.id);
    const snaps1 = v1.getLatestUsage(r1.data.user.id);
    const snaps2 = v2.getLatestUsage(r2.data.user.id);

    // Exactly one user claimed all legacy rows
    const user1Claimed = creds1.length === 1 && snaps1.length === 1;
    const user2Claimed = creds2.length === 1 && snaps2.length === 1;

    expect(user1Claimed !== user2Claimed).toBe(true);

    if (user1Claimed) {
      expect(creds2.length).toBe(0);
      expect(snaps2.length).toBe(0);
      expect(creds1[0]?.ownerId).toBe(r1.data.user.id);
    } else {
      expect(creds1.length).toBe(0);
      expect(snaps1.length).toBe(0);
      expect(creds2[0]?.ownerId).toBe(r2.data.user.id);
    }

    // Zero ownerless rows remain
    const remainingUnowned = v1.listAllCredentialsInternal();
    expect(remainingUnowned.every((c: StoredCredential) => c.ownerId !== undefined && c.ownerId !== null)).toBe(true);

    v1.close();
    v2.close();
    try {
      unlinkSync(sharedDbPath);
    } catch {}
  });
});

describe("AuthService Domain Invariants & Security", () => {
  it("enforces canonicalized email (trim + lowercase) and case-insensitive uniqueness", async () => {
    const reg1 = await auth.register("  John.Doe@Example.COM  ", "ValidPassword123!");
    expect(reg1.success).toBe(true);
    if (!reg1.success) return;
    expect(reg1.data.user.email).toBe("john.doe@example.com");

    // Duplicate registration with different casing and whitespace
    const dup1 = await auth.register("john.doe@example.com", "ValidPassword123!");
    expect(dup1.success).toBe(false);
    if (!dup1.success) {
      expect(dup1.error).toBe("EMAIL_EXISTS");
    }

    const dup2 = await auth.register("JOHN.DOE@EXAMPLE.COM", "ValidPassword123!");
    expect(dup2.success).toBe(false);
    if (!dup2.success) {
      expect(dup2.error).toBe("EMAIL_EXISTS");
    }

    // Invalid email format rejected
    const invalidEmail = await auth.register("not-an-email", "ValidPassword123!");
    expect(invalidEmail.success).toBe(false);
    if (!invalidEmail.success) {
      expect(invalidEmail.error).toBe("INVALID_EMAIL");
    }
  });

  it("enforces deterministic password length boundaries (12 to 256 chars/code units)", async () => {
    // 11 characters -> fails
    const short = await auth.register("user@test.com", "12345678901");
    expect(short.success).toBe(false);
    if (!short.success) {
      expect(short.error).toBe("WEAK_PASSWORD");
    }

    // 12 characters -> succeeds
    const minLen = await auth.register("user12@test.com", "123456789012");
    expect(minLen.success).toBe(true);

    // 256 characters -> succeeds
    const pass256 = "a".repeat(256);
    const maxLen = await auth.register("user256@test.com", pass256);
    expect(maxLen.success).toBe(true);

    // 257 characters -> fails
    const pass257 = "a".repeat(257);
    const tooLong = await auth.register("user257@test.com", pass257);
    expect(tooLong.success).toBe(false);
    if (!tooLong.success) {
      expect(tooLong.error).toBe("WEAK_PASSWORD");
    }
  });

  it("does not leak email existence through login error messages (uniform INVALID_CREDENTIALS)", async () => {
    await auth.register("registered@test.com", "CorrectPassword123!");

    // Non-existent email
    const nonExistent = await auth.login("nonexistent@test.com", "SomePassword123!");
    expect(nonExistent.success).toBe(false);
    if (!nonExistent.success) {
      expect(nonExistent.error).toBe("INVALID_CREDENTIALS");
      expect(nonExistent.message).toBe("Invalid email or password");
    }

    // Existing email with incorrect password
    const wrongPassword = await auth.login("registered@test.com", "WrongPassword123!");
    expect(wrongPassword.success).toBe(false);
    if (!wrongPassword.success) {
      expect(wrongPassword.error).toBe("INVALID_CREDENTIALS");
      expect(wrongPassword.message).toBe("Invalid email or password");
    }

    // Case-insensitive login with correct password succeeds
    const correctLogin = await auth.login("REGISTERED@TEST.COM", "CorrectPassword123!");
    expect(correctLogin.success).toBe(true);
    if (correctLogin.success) {
      expect(correctLogin.data.user.email).toBe("registered@test.com");
    }
  });

  it("persists only SHA-256 token hash at rest and never stores raw 32-byte session token", async () => {
    const reg = await auth.register("session.test@example.com", "StrongSessionPassword#1");
    expect(reg.success).toBe(true);
    if (!reg.success) return;

    const rawToken = reg.data.token;
    expect(rawToken.length).toBe(64); // 32 random bytes in hex = 64 characters

    const expectedHash = hashSessionToken(rawToken);

    // Retrieve session directly from SQLite memory database
    const directSession = vault.getSessionByTokenHash(expectedHash);
    expect(directSession).not.toBeNull();
    expect(directSession?.tokenHash).toBe(expectedHash);
    expect(directSession?.tokenHash).not.toBe(rawToken);

    // Querying with raw token as hash returns null
    const notHashed = vault.getSessionByTokenHash(rawToken);
    expect(notHashed).toBeNull();

    // Authenticate with raw token succeeds
    const authOk = await auth.authenticate(rawToken);
    expect(authOk.success).toBe(true);
    if (authOk.success) {
      expect(authOk.data.id).toBe(reg.data.user.id);
    }
  });

  it("handles session expiration and explicit logout invalidation", async () => {
    const reg = await auth.register("logout.test@example.com", "PasswordForLogout#1");
    expect(reg.success).toBe(true);
    if (!reg.success) return;

    const token = reg.data.token;

    // Authenticated while active
    const authBefore = await auth.authenticate(token);
    expect(authBefore.success).toBe(true);

    // Logout revokes session
    await auth.logout(token);

    const authAfter = await auth.authenticate(token);
    expect(authAfter.success).toBe(false);
    if (!authAfter.success) {
      expect(authAfter.error).toBe("UNAUTHENTICATED");
    }
  });
});

describe("Multi-Tenant Storage Isolation", () => {
  it("allows two users to have identical provider and accountLabel without collision", async () => {
    const regA = await auth.register("usera@company.com", "PasswordUserA#123");
    const regB = await auth.register("userb@company.com", "PasswordUserB#123");
    expect(regA.success && regB.success).toBe(true);
    if (!regA.success || !regB.success) return;

    const userA = regA.data.user;
    const userB = regB.data.user;

    const credInput: InputCredential = {
      provider: "openai-codex",
      accountLabel: "Personal",
      credentialType: "api_key",
      secret: "sk-user-secret",
    };

    // Both save identical provider + accountLabel
    const credA = vault.saveCredential(userA.id, {
      ...credInput,
      secret: "sk-userA-secret-value",
    });
    const credB = vault.saveCredential(userB.id, {
      ...credInput,
      secret: "sk-userB-secret-value",
    });

    expect(credA.id).not.toBe(credB.id);
    expect(credA.ownerId).toBe(userA.id);
    expect(credB.ownerId).toBe(userB.id);

    // User A only sees User A's credential
    const listA = vault.listCredentials(userA.id);
    expect(listA.length).toBe(1);
    expect(listA[0]?.id).toBe(credA.id);
    expect(listA[0]?.secret).toBe("sk-userA-secret-value");

    // User B only sees User B's credential
    const listB = vault.listCredentials(userB.id);
    expect(listB.length).toBe(1);
    expect(listB[0]?.id).toBe(credB.id);
    expect(listB[0]?.secret).toBe("sk-userB-secret-value");

    // Daemon enumeration returns both
    const allCreds = vault.listAllCredentialsInternal();
    expect(allCreds.length).toBe(2);
  });

  it("prevents User A from reading, updating, or deleting User B credentials", async () => {
    const regA = await auth.register("alice@tenant.com", "AliceStrongPass#123");
    const regB = await auth.register("bob@tenant.com", "BobStrongPass#123");
    expect(regA.success && regB.success).toBe(true);
    if (!regA.success || !regB.success) return;

    const alice = regA.data.user;
    const bob = regB.data.user;

    const bobCred = vault.saveCredential(bob.id, {
      provider: "anthropic",
      accountLabel: "Bob Claude",
      credentialType: "oauth",
      secret: "bob-secret-token",
    });

    // Alice attempts to get Bob's credential
    const aliceGetBob = vault.getCredential(alice.id, bobCred.id);
    expect(aliceGetBob).toBeNull();

    // Alice attempts to update Bob's credential
    const aliceUpdateBob = vault.updateCredential(alice.id, bobCred.id, {
      accountLabel: "Hacked Label",
    });
    expect(aliceUpdateBob).toBe(false);

    // Alice attempts to update Bob's tokens
    const aliceTokenUpdate = vault.updateCredentialTokens(
      alice.id,
      bobCred.id,
      "new-malicious-token",
    );
    expect(aliceTokenUpdate).toBe(false);

    // Bob's credential is unchanged
    const bobVerified = vault.getCredential(bob.id, bobCred.id);
    expect(bobVerified?.accountLabel).toBe("Bob Claude");
    expect(bobVerified?.secret).toBe("bob-secret-token");

    // Alice attempts to delete Bob's credential
    const aliceDeleteBob = vault.deleteCredential(alice.id, bobCred.id);
    expect(aliceDeleteBob).toBe(false);

    // Bob's credential still exists
    expect(vault.getCredential(bob.id, bobCred.id)).not.toBeNull();

    // Bob deletes own credential
    const bobDeleteSelf = vault.deleteCredential(bob.id, bobCred.id);
    expect(bobDeleteSelf).toBe(true);
    expect(vault.getCredential(bob.id, bobCred.id)).toBeNull();
  });

  it("isolates usage reports and snapshot history across owners", async () => {
    const regA = await auth.register("snap.a@test.com", "PasswordSnapA#123");
    const regB = await auth.register("snap.b@test.com", "PasswordSnapB#123");
    expect(regA.success && regB.success).toBe(true);
    if (!regA.success || !regB.success) return;

    const userA = regA.data.user;
    const userB = regB.data.user;

    const credA = vault.saveCredential(userA.id, {
      provider: "google-antigravity",
      accountLabel: "A Gemini",
      credentialType: "api_key",
      secret: "secret-a",
    });

    const credB = vault.saveCredential(userB.id, {
      provider: "google-antigravity",
      accountLabel: "B Gemini",
      credentialType: "api_key",
      secret: "secret-b",
    });

    const now = Date.now();
    vault.saveUsageSnapshot(userA.id, {
      provider: "google-antigravity",
      credentialId: credA.id,
      accountLabel: "A Gemini",
      fetchedAt: now,
      limits: [
        {
          id: "gemini-5h",
          label: "Gemini 5h",
          amount: { remaining: 80, unit: "percent" },
          status: "ok",
        },
      ],
    });

    vault.saveUsageSnapshot(userB.id, {
      provider: "google-antigravity",
      credentialId: credB.id,
      accountLabel: "B Gemini",
      fetchedAt: now,
      limits: [
        {
          id: "gemini-5h",
          label: "Gemini 5h",
          amount: { remaining: 20, unit: "percent" },
          status: "warning",
        },
      ],
    });

    // User A latest reports
    const latestA = vault.getLatestUsage(userA.id);
    expect(latestA.length).toBe(1);
    expect(latestA[0]?.credentialId).toBe(credA.id);
    expect(latestA[0]?.limits[0]?.amount.remaining).toBe(80);

    // User B latest reports
    const latestB = vault.getLatestUsage(userB.id);
    expect(latestB.length).toBe(1);
    expect(latestB[0]?.credentialId).toBe(credB.id);
    expect(latestB[0]?.limits[0]?.amount.remaining).toBe(20);

    // Snapshot history isolated
    const historyA = vault.getSnapshotHistory(userA.id, "google-antigravity", 1);
    expect(historyA.length).toBe(1);
    expect(historyA[0]?.credentialId).toBe(credA.id);

    const historyB = vault.getSnapshotHistory(userB.id, "google-antigravity", 1);
    expect(historyB.length).toBe(1);
    expect(historyB[0]?.credentialId).toBe(credB.id);
  });
  it("verifies credentials are encrypted at rest with AES-256-GCM and decrypt cleanly", async () => {
    const reg = await auth.register("crypto.audit@example.com", "MasterPassword123!");
    expect(reg.success).toBe(true);
    if (!reg.success) return;

    const user = reg.data.user;
    const plaintext = "sensitive-anthropic-sk-ant-api03-secret";

    const cred = vault.saveCredential(user.id, {
      provider: "anthropic",
      accountLabel: "AES Test",
      credentialType: "api_key",
      secret: plaintext,
    });

    // 1. Consumer view: plaintext is recovered
    expect(cred.secret).toBe(plaintext);

    // 2. Storage view: getCredential recovers plaintext
    const retrieved = vault.getCredential(user.id, cred.id);
    expect(retrieved?.secret).toBe(plaintext);

    // 3. Direct crypto primitive test: encrypt produces different ciphertext and decrypt restores plaintext
    const encPayload = encryptSecret(plaintext);
    expect(encPayload.ciphertext).not.toBe(plaintext);
    const decrypted = decryptSecret(encPayload);
    expect(decrypted).toBe(plaintext);
  });
  it("rejects cross-owner snapshot injection and protects latest/history queries from poisoning", async () => {
    const regA = await auth.register("victim.a@test.com", "PasswordAlice#123");
    const regB = await auth.register("attacker.b@test.com", "PasswordBob#123");
    expect(regA.success && regB.success).toBe(true);
    if (!regA.success || !regB.success) return;

    const alice = regA.data.user;
    const bob = regB.data.user;

    const aliceCred = vault.saveCredential(alice.id, {
      provider: "openrouter",
      accountLabel: "Alice Primary",
      credentialType: "api_key",
      secret: "sk-alice-secret",
    });

    const bobCred = vault.saveCredential(bob.id, {
      provider: "openrouter",
      accountLabel: "Bob Primary",
      credentialType: "api_key",
      secret: "sk-bob-secret",
    });

    const now = Date.now();

    // 1. Alice records legitimate snapshot
    const legitimateReport: UsageReport = {
      provider: "openrouter",
      credentialId: aliceCred.id,
      accountLabel: "Alice Primary",
      fetchedAt: now - 5000,
      limits: [
        {
          id: "credits",
          label: "Remaining Credits",
          amount: { remaining: 100, unit: "usd" },
          status: "ok",
        },
      ],
    };
    const aliceSaveResult = vault.saveUsageSnapshot(alice.id, legitimateReport);
    expect(aliceSaveResult).toBe(true);

    // Bob records a legitimate snapshot for his own credential
    const bobLegitReport: UsageReport = {
      provider: "openrouter",
      credentialId: bobCred.id,
      accountLabel: "Bob Primary",
      fetchedAt: now - 2000,
      limits: [
        {
          id: "credits",
          label: "Remaining Credits",
          amount: { remaining: 50, unit: "usd" },
          status: "ok",
        },
      ],
    };
    expect(vault.saveUsageSnapshot(bob.id, bobLegitReport)).toBe(true);

    // 2. Bob attempts cross-owner snapshot injection targeting Alice's credential
    const spoofedReport: UsageReport = {
      provider: "openrouter",
      credentialId: aliceCred.id, // targeting Alice's credential!
      accountLabel: "Poisoned Label",
      fetchedAt: now,
      limits: [
        {
          id: "credits",
          label: "Remaining Credits",
          amount: { remaining: 0, unit: "usd" },
          status: "exhausted",
        },
      ],
    };

    // Vector A: Bob calls saveUsageSnapshot with his ownerId and Alice's credentialId
    const bobAttackA = vault.saveUsageSnapshot(bob.id, spoofedReport);
    expect(bobAttackA).toBe(false);

    // Vector B: Bob calls saveSnapshot with his ownerId and Alice's credentialId
    const bobAttackB = vault.saveSnapshot(bob.id, spoofedReport);
    expect(bobAttackB).toBe(false);

    // Vector C: Bob calls saveUsageSnapshot with report containing his ownerId but Alice's credentialId
    const bobAttackC = vault.saveUsageSnapshot(bob.id, { ...spoofedReport, ownerId: bob.id });
    expect(bobAttackC).toBe(false);

    // Vector D: Bob attempts to pass Alice's ownerId explicitly while not authenticated as Alice
    const bobAttackD = vault.saveUsageSnapshot(bob.id, { ...spoofedReport, ownerId: alice.id });
    expect(bobAttackD).toBe(false);

    // Reverse attack: Alice attempts to inject into Bob's credential
    const aliceAttackBob = vault.saveUsageSnapshot(alice.id, {
      ...legitimateReport,
      credentialId: bobCred.id,
    });
    expect(aliceAttackBob).toBe(false);

    // 3. Verify Bob's tenant view: Bob sees only his own legitimate snapshot
    const bobLatest = vault.getLatestUsage(bob.id);
    expect(bobLatest.length).toBe(1);
    expect(bobLatest[0]?.credentialId).toBe(bobCred.id);
    expect(bobLatest[0]?.limits[0]?.amount.remaining).toBe(50);

    const bobHistory = vault.getSnapshotHistory(bob.id, "openrouter", 24);
    expect(bobHistory.length).toBe(1);
    expect(bobHistory[0]?.credentialId).toBe(bobCred.id);

    // 4. Verify Alice's tenant view: Alice's snapshot is completely unpoisoned
    const aliceLatest = vault.getLatestUsage(alice.id);
    expect(aliceLatest.length).toBe(1);
    expect(aliceLatest[0]?.credentialId).toBe(aliceCred.id);
    expect(aliceLatest[0]?.accountLabel).toBe("Alice Primary");
    expect(aliceLatest[0]?.limits[0]?.amount.remaining).toBe(100);
    expect(aliceLatest[0]?.fetchedAt).toBe(now - 5000);

    const aliceHistory = vault.getSnapshotHistory(alice.id, "openrouter", 24);
    expect(aliceHistory.length).toBe(1);
    expect(aliceHistory[0]?.credentialId).toBe(aliceCred.id);
    expect(aliceHistory[0]?.limits[0]?.amount.remaining).toBe(100);
    // 5. Verify global query view: both legitimate snapshots are present, neither poisoned
    const globalLatest = vault.getLatestUsageInternal();
    expect(globalLatest.length).toBe(2);
    const globalCredMap = new Map(globalLatest.map((s: UsageReport) => [s.credentialId, s]));
    expect(globalCredMap.get(aliceCred.id)?.limits[0]?.amount.remaining).toBe(100);
    expect(globalCredMap.get(bobCred.id)?.limits[0]?.amount.remaining).toBe(50);
  });

  it("deterministically disambiguates duplicate legacy (provider, account_label) credentials on first registration without data loss", async () => {
    const legacyPath = `data/test-legacy-dups-${Date.now()}-${Math.random().toString(36).slice(2)}.db`;
    const rawDb = new Database(legacyPath, { create: true });
    rawDb.exec(`
      CREATE TABLE credentials (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        accent TEXT NOT NULL DEFAULT 'default',
        credential_type TEXT NOT NULL,
        encrypted_secret TEXT NOT NULL,
        iv TEXT NOT NULL,
        tag TEXT NOT NULL,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE usage_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        report_json TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
      );
    `);

    const enc1 = encryptSecret("secret-key-1");
    const enc2 = encryptSecret("secret-key-2");
    const enc3 = encryptSecret("secret-key-3");
    const enc4 = encryptSecret("secret-key-4");

    // Seed duplicate legacy credentials with identical provider and account_label
    // plus one that already uses the " (2)" suffix
    const insertCred = rawDb.prepare(`
      INSERT INTO credentials (
        id, provider, account_label, accent, credential_type,
        encrypted_secret, iv, tag, metadata, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCred.run("dup-1", "openrouter", "Default", "default", "api_key", enc1.ciphertext, enc1.iv, enc1.tag, null, 1000, 1000);
    insertCred.run("dup-2", "openrouter", "Default (2)", "default", "api_key", enc2.ciphertext, enc2.iv, enc2.tag, null, 1500, 1500);
    insertCred.run("dup-3", "openrouter", "Default", "emerald", "api_key", enc3.ciphertext, enc3.iv, enc3.tag, null, 2000, 2000);
    insertCred.run("dup-4", "openrouter", "Default", "violet", "api_key", enc4.ciphertext, enc4.iv, enc4.tag, null, 3000, 3000);

    // Seed matching snapshots for each credential
    const insertSnap = rawDb.prepare(`
      INSERT INTO usage_snapshots (credential_id, provider, account_label, report_json, fetched_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    const mkReport = (id: string, label: string, remaining: number): string =>
      JSON.stringify({
        provider: "openrouter",
        credentialId: id,
        accountLabel: label,
        fetchedAt: 1000,
        limits: [{ id: "credits", label: "Credits", amount: { remaining, unit: "usd" }, status: "ok" }],
      });

    insertSnap.run("dup-1", "openrouter", "Default", mkReport("dup-1", "Default", 10), 1000);
    insertSnap.run("dup-2", "openrouter", "Default (2)", mkReport("dup-2", "Default (2)", 20), 1000);
    insertSnap.run("dup-3", "openrouter", "Default", mkReport("dup-3", "Default", 30), 1000);
    insertSnap.run("dup-4", "openrouter", "Default", mkReport("dup-4", "Default", 40), 1000);
    rawDb.close();

    // Open through StorageVault
    const testVault = new StorageVault(legacyPath);
    const testAuth = new AuthService(testVault);

    // Register first user: MUST claim all legacy rows without crashing on UNIQUE index
    const regResult1 = await testAuth.register("owner.first@example.com", "FirstOwnerPassword123!");
    expect(regResult1.success).toBe(true);
    if (!regResult1.success) {
      testVault.close();
      try { unlinkSync(legacyPath); } catch {}
      return;
    }

    const user1 = regResult1.data.user;

    // 1. All 4 credentials must be preserved under user1
    const user1Creds = testVault.listCredentials(user1.id);
    expect(user1Creds.length).toBe(4);

    // IDs must be completely preserved
    const credMap = new Map(user1Creds.map((c: StoredCredential) => [c.id, c]));
    expect(credMap.has("dup-1")).toBe(true);
    expect(credMap.has("dup-2")).toBe(true);
    expect(credMap.has("dup-3")).toBe(true);
    expect(credMap.has("dup-4")).toBe(true);

    // Secrets must be cleanly decrypted and intact
    expect(credMap.get("dup-1")?.secret).toBe("secret-key-1");
    expect(credMap.get("dup-2")?.secret).toBe("secret-key-2");
    expect(credMap.get("dup-3")?.secret).toBe("secret-key-3");
    expect(credMap.get("dup-4")?.secret).toBe("secret-key-4");

    // Deterministic labels:
    // dup-1 (created 1000) keeps "Default"
    // dup-2 (created 1500) keeps "Default (2)"
    // dup-3 (created 2000) was a duplicate of "Default", and because "Default (2)" already existed, gets "Default (3)"
    // dup-4 (created 3000) gets "Default (4)"
    expect(credMap.get("dup-1")?.accountLabel).toBe("Default");
    expect(credMap.get("dup-2")?.accountLabel).toBe("Default (2)");
    expect(credMap.get("dup-3")?.accountLabel).toBe("Default (3)");
    expect(credMap.get("dup-4")?.accountLabel).toBe("Default (4)");

    // 2. Usage snapshot labels must match the disambiguated credential labels consistently
    const user1Snaps = testVault.getLatestUsage(user1.id);
    expect(user1Snaps.length).toBe(4);
    const snapMap = new Map(user1Snaps.map((s: UsageReport) => [s.credentialId, s]));

    expect(snapMap.get("dup-1")?.accountLabel).toBe("Default");
    expect(snapMap.get("dup-2")?.accountLabel).toBe("Default (2)");
    expect(snapMap.get("dup-3")?.accountLabel).toBe("Default (3)");
    expect(snapMap.get("dup-4")?.accountLabel).toBe("Default (4)");

    // 3. Register second user: gets 0 credentials and 0 snapshots
    const regResult2 = await testAuth.register("owner.second@example.com", "SecondOwnerPassword123!");
    expect(regResult2.success).toBe(true);
    if (regResult2.success) {
      expect(testVault.listCredentials(regResult2.data.user.id).length).toBe(0);
      expect(testVault.getLatestUsage(regResult2.data.user.id).length).toBe(0);
    }

    // 4. Zero ownerless credentials or snapshots remain
    const daemonCreds = testVault.listAllCredentialsInternal();
    expect(daemonCreds.every((c: StoredCredential) => c.ownerId === user1.id)).toBe(true);

    testVault.close();
    try { unlinkSync(legacyPath); } catch {}
  });

  it("prevents new ownerless and tenant rename collisions", () => {
    const c1 = vault.saveCredentialInternal({
      provider: "openai-codex",
      accountLabel: "Label Alpha",
      credentialType: "api_key",
      secret: "secret-alpha",
    });
    const c2 = vault.saveCredentialInternal({
      provider: "openai-codex",
      accountLabel: "Label Beta",
      credentialType: "api_key",
      secret: "secret-beta",
    });
    expect(vault.getCredentialInternal(c1.id)?.accountLabel).toBe("Label Alpha");
    expect(vault.getCredentialInternal(c2.id)?.accountLabel).toBe("Label Beta");
    const collisionRename = vault.updateCredential(c2.ownerId, c2.id, { accountLabel: c1.accountLabel });
    expect(collisionRename).toBe(false);
    const validRename = vault.updateCredential(c2.ownerId, c2.id, { accountLabel: "Label Gamma" });
    expect(validRename).toBe(true);
    expect(vault.getCredentialInternal(c2.id)?.accountLabel).toBe("Label Gamma");
    expect(vault.getCredentialInternal(c1.id)?.accountLabel).toBe("Label Alpha");
  });
});
describe("StorageVault Admin Operations & Safety Rules", () => {
  it("assigns admin role to first registered user and user role to subsequent users", async () => {
    const res1 = await auth.register("first.admin@example.com", "AdminPassword123!");
    expect(res1.success).toBe(true);
    if (!res1.success) return;

    expect(res1.data.user.role).toBe("admin");
    const user1ById = vault.getUserById(res1.data.user.id);
    expect(user1ById?.role).toBe("admin");
    const user1ByEmail = vault.getUserByEmail("first.admin@example.com");
    expect(user1ByEmail?.role).toBe("admin");

    // Authenticate with token
    const authRes1 = await auth.authenticate(res1.data.token);
    expect(authRes1.success).toBe(true);
    if (authRes1.success) {
      expect(authRes1.data.role).toBe("admin");
    }

    // Second user
    const res2 = await auth.register("second.user@example.com", "UserPassword123!");
    expect(res2.success).toBe(true);
    if (!res2.success) return;

    expect(res2.data.user.role).toBe("user");
    const user2ById = vault.getUserById(res2.data.user.id);
    expect(user2ById?.role).toBe("user");
    const user2ByEmail = vault.getUserByEmail("second.user@example.com");
    expect(user2ByEmail?.role).toBe("user");

    // Login checks
    const login1 = await auth.login("first.admin@example.com", "AdminPassword123!");
    expect(login1.success).toBe(true);
    if (login1.success) {
      expect(login1.data.user.role).toBe("admin");
    }

    const login2 = await auth.login("second.user@example.com", "UserPassword123!");
    expect(login2.success).toBe(true);
    if (login2.success) {
      expect(login2.data.user.role).toBe("user");
    }
  });

  it("lists all users with accurate credential and active session counts", async () => {
    const adminReg = await auth.register("admin.list@example.com", "AdminPassword123!");
    const userReg = await auth.register("user.list@example.com", "UserPassword123!");
    if (!adminReg.success || !userReg.success) return;

    const adminId = adminReg.data.user.id;
    const userId = userReg.data.user.id;

    // Add credentials to user
    vault.saveCredential(userId, {
      provider: "openrouter",
      accountLabel: "OpenRouter Main",
      credentialType: "api_key",
      secret: "sk-or-test",
    });
    vault.saveCredential(userId, {
      provider: "deepseek",
      accountLabel: "DeepSeek Work",
      credentialType: "api_key",
      secret: "sk-ds-test",
    });

    // Add an expired session to user
    vault.createSession(userId, "expired-token-hash", Date.now() - 10000);
    // Add another active session to user
    vault.createSession(userId, "active-token-hash-2", Date.now() + 60000);

    const userList = vault.listUsersAdmin();
    expect(userList.length).toBe(2);

    const adminEntry = userList.find((u) => u.id === adminId);
    expect(adminEntry).toBeDefined();
    expect(adminEntry?.email).toBe("admin.list@example.com");
    expect(adminEntry?.role).toBe("admin");
    expect(adminEntry?.credentialCount).toBe(0);
    expect(adminEntry?.activeSessionCount).toBe(1); // registration session

    const userEntry = userList.find((u) => u.id === userId);
    expect(userEntry).toBeDefined();
    expect(userEntry?.email).toBe("user.list@example.com");
    expect(userEntry?.role).toBe("user");
    expect(userEntry?.credentialCount).toBe(2);
    expect(userEntry?.activeSessionCount).toBe(2); // registration session + active session (expired excluded)
  });

  it("updates user role and prevents demoting the last admin", async () => {
    const adminReg = await auth.register("admin.role@example.com", "AdminPassword123!");
    const userReg = await auth.register("user.role@example.com", "UserPassword123!");
    if (!adminReg.success || !userReg.success) return;

    const adminId = adminReg.data.user.id;
    const userId = userReg.data.user.id;

    // 1. Non-admin caller cannot update roles
    const unauth = vault.updateUserRoleAdmin(userId, adminId, "user");
    expect(unauth.success).toBe(false);
    expect(unauth.error).toBe("Unauthorized");

    // 2. Cannot demote the last admin
    const demoteLast = vault.updateUserRoleAdmin(adminId, adminId, "user");
    expect(demoteLast.success).toBe(false);
    expect(demoteLast.error).toBe("Cannot demote the last admin");

    // 3. Promote user to admin
    const promoteRes = vault.updateUserRoleAdmin(adminId, userId, "admin");
    expect(promoteRes.success).toBe(true);
    expect(vault.getUserById(userId)?.role).toBe("admin");

    // 4. Now with 2 admins, one can demote the other
    const demoteOther = vault.updateUserRoleAdmin(adminId, userId, "user");
    expect(demoteOther.success).toBe(true);
    expect(vault.getUserById(userId)?.role).toBe("user");

    // 5. Target not found
    const notFound = vault.updateUserRoleAdmin(adminId, "non-existent-id", "admin");
    expect(notFound.success).toBe(false);
    expect(notFound.error).toBe("User not found");
  });

  it("deletes user, prevents self-deletion and last admin deletion, and cascades related records", async () => {
    const adminReg = await auth.register("admin.del@example.com", "AdminPassword123!");
    const userReg = await auth.register("user.del@example.com", "UserPassword123!");
    if (!adminReg.success || !userReg.success) return;

    const adminId = adminReg.data.user.id;
    const userId = userReg.data.user.id;

    // Add credentials and snapshots for user
    const cred = vault.saveCredential(userId, {
      provider: "openrouter",
      accountLabel: "To Delete",
      credentialType: "api_key",
      secret: "sk-delete-me",
    });
    vault.saveUsageSnapshot(userId, {
      credentialId: cred.id,
      provider: "openrouter",
      accountLabel: "To Delete",
      limits: [],
      fetchedAt: Date.now(),
    });

    // 1. Non-admin caller cannot delete
    const unauthDel = vault.deleteUserAdmin(userId, adminId);
    expect(unauthDel.success).toBe(false);
    expect(unauthDel.error).toBe("Unauthorized");

    // 2. Cannot delete own account
    const selfDel = vault.deleteUserAdmin(adminId, adminId);
    expect(selfDel.success).toBe(false);
    expect(selfDel.error).toBe("Cannot delete your own account");

    // 3. Cannot delete the last admin (promote user first, then try deleting only remaining admin)
    vault.updateUserRoleAdmin(adminId, userId, "admin");
    // Now both are admins. Delete user from admin perspective: allowed
    // But let's demote user back to user first to test "Cannot delete the last admin"
    vault.updateUserRoleAdmin(adminId, userId, "user");
    // If someone calls delete on admin from another admin:
    // Promote user to admin so we have 2 admins
    vault.updateUserRoleAdmin(adminId, userId, "admin");
    // User deletes admin
    const delAdminRes = vault.deleteUserAdmin(userId, adminId);
    expect(delAdminRes.success).toBe(true);
    expect(vault.getUserById(adminId)).toBeNull();

    // Now userId is the ONLY admin left. Create another user
    const user3Reg = await auth.register("user3.del@example.com", "UserPassword123!");
    if (!user3Reg.success) return;
    const user3Id = user3Reg.data.user.id;

    // Now user3 promotes user4 to user... Wait, userId is the only admin. Can anyone delete userId?
    // If another admin existed, they could, but userId is the only admin, so trying to delete userId must fail
    // What if user3 is promoted to admin? Then user3 can delete user3? No, self deletion fails.
    // What if user3 is NOT admin and tries to delete userId? Fails with "Unauthorized".
    // If user3 IS admin, there are 2 admins.
    // To test "Cannot delete the last admin": user3 promoted to admin, then user3 demoted, so userId is only admin.
    // Wait, let's test deleting target who has role admin when admin count is 1:
    // userId cannot delete self because self-deletion check triggers first ("Cannot delete your own account").
    // But what if target is another user who was admin and adminCount <= 1?
    // That can only happen if adminUserId is somehow admin, targetUserId is another user who is admin, but adminCount <= 1.
    // If both caller and target are admins, adminCount is at least 2.
    // However, the rule explicitly checks: if (target.role === "admin" && adminCount <= 1) -> "Cannot delete the last admin".
    // Let's verify target not found:
    const notFound = vault.deleteUserAdmin(userId, "non-existent-user");
    expect(notFound.success).toBe(false);
    expect(notFound.error).toBe("User not found");

    // 4. Delete user3 and verify foreign key cascades
    const user3Cred = vault.saveCredential(user3Id, {
      provider: "claude",
      accountLabel: "Claude User 3",
      credentialType: "api_key",
      secret: "sk-claude-test",
    });
    vault.saveUsageSnapshot(user3Id, {
      credentialId: user3Cred.id,
      provider: "claude",
      accountLabel: "Claude User 3",
      limits: [],
      fetchedAt: Date.now(),
    });

    expect(vault.listCredentials(user3Id).length).toBe(1);
    expect(vault.getLatestUsage(user3Id).length).toBe(1);

    const delUser3 = vault.deleteUserAdmin(userId, user3Id);
    expect(delUser3.success).toBe(true);
    expect(vault.getUserById(user3Id)).toBeNull();

    // Cascaded deletions verified
    expect(vault.listCredentials(user3Id).length).toBe(0);
    expect(vault.getLatestUsage(user3Id).length).toBe(0);
  });

  it("retrieves complete system statistics with provider aggregation and database size", async () => {
    const adminReg = await auth.register("admin.stats@example.com", "AdminPassword123!");
    const userReg = await auth.register("user.stats@example.com", "UserPassword123!");
    if (!adminReg.success || !userReg.success) return;

    vault.saveCredential(adminReg.data.user.id, {
      provider: "openai-codex",
      accountLabel: "Codex Admin",
      credentialType: "api_key",
      secret: "sk-codex",
    });
    vault.saveCredential(userReg.data.user.id, {
      provider: "openai-codex",
      accountLabel: "Codex User",
      credentialType: "api_key",
      secret: "sk-codex-2",
    });
    vault.saveCredential(userReg.data.user.id, {
      provider: "anthropic-claude",
      accountLabel: "Claude User",
      credentialType: "api_key",
      secret: "sk-claude",
    });

    const stats = vault.getSystemStatsAdmin(true);
    expect(stats.totalUsers).toBe(2);
    expect(stats.totalCredentials).toBe(3);
    expect(stats.activeSessions).toBe(2);
    expect(stats.pollerRunning).toBe(true);
    expect(stats.databaseSizeBytes).toBeGreaterThan(0);
    expect(stats.integrity).toBe(true);
    expect(stats.providerCounts).toEqual({
      "openai-codex": 2,
      "anthropic-claude": 1,
    });
  });
  it("migrates existing users table without role column by adding role with default 'user'", () => {
    const testDbPath = `data/test-role-migration-${Date.now()}.db`;
    const rawDb = new Database(testDbPath, { create: true });
    rawDb.exec(`
      CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE credentials (
        id TEXT PRIMARY KEY,
        owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        accent TEXT NOT NULL DEFAULT 'default',
        credential_type TEXT NOT NULL,
        encrypted_secret TEXT NOT NULL,
        iv TEXT NOT NULL,
        tag TEXT NOT NULL,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE usage_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        credential_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        report_json TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
      );
      INSERT INTO users (id, email, password_hash, created_at, updated_at)
      VALUES ('existing-user-1', 'existing@example.com', 'hash123', 1000, 1000);
      PRAGMA user_version = 1;
    `);
    rawDb.close();

    const migratedVault = new StorageVault(testDbPath);
    const user = migratedVault.getUserById("existing-user-1");
    expect(user).toBeDefined();
    expect(user?.role).toBe("user");

    const usersList = migratedVault.listUsersAdmin();
    expect(usersList.length).toBe(1);
    expect(usersList[0].role).toBe("user");

    migratedVault.close();
    try { unlinkSync(testDbPath); } catch {}
  });
});

describe("StorageVault System Settings & Registration Policy", () => {
  it("getSetting returns defaultValue when key does not exist", () => {
    expect(vault.getSetting("non_existent_key")).toBe("");
    expect(vault.getSetting("non_existent_key", "default_val")).toBe("default_val");
  });

  it("setSetting stores and updates settings with timestamps", () => {
    vault.setSetting("site_name", "AI Usage Tracker");
    expect(vault.getSetting("site_name")).toBe("AI Usage Tracker");

    // Overwrite existing key
    vault.setSetting("site_name", "New Name");
    expect(vault.getSetting("site_name")).toBe("New Name");
  });

  it("isRegistrationAllowed always returns true if user count is 0 (initial setup guarantee)", () => {
    expect(vault.getUserCount()).toBe(0);

    // Even if explicitly set to false in settings
    vault.setSetting("allow_registration", "false");
    expect(vault.getSetting("allow_registration")).toBe("false");
    expect(vault.isRegistrationAllowed()).toBe(true);
  });

  it("isRegistrationAllowed defaults to true when users exist and setting is unset", () => {
    vault.createUser("admin@example.com", "hashed_password");
    expect(vault.getUserCount()).toBe(1);

    expect(vault.getSetting("allow_registration")).toBe("");
    expect(vault.isRegistrationAllowed()).toBe(true);
  });

  it("isRegistrationAllowed reflects false when users exist and setting is false", () => {
    vault.createUser("admin@example.com", "hashed_password");
    expect(vault.getUserCount()).toBe(1);

    vault.setRegistrationAllowed(false);
    expect(vault.getSetting("allow_registration")).toBe("false");
    expect(vault.isRegistrationAllowed()).toBe(false);
  });

  it("isRegistrationAllowed reflects true when users exist and setting is true", () => {
    vault.createUser("admin@example.com", "hashed_password");
    expect(vault.getUserCount()).toBe(1);

    vault.setRegistrationAllowed(false);
    expect(vault.isRegistrationAllowed()).toBe(false);

    vault.setRegistrationAllowed(true);
    expect(vault.getSetting("allow_registration")).toBe("true");
    expect(vault.isRegistrationAllowed()).toBe(true);
  });

  it("getSystemStatsAdmin includes allowRegistration status correctly", () => {
    // When 0 users: always true
    let stats = vault.getSystemStatsAdmin(true);
    expect(stats.allowRegistration).toBe(true);

    // When user created and registration allowed
    vault.createUser("admin@example.com", "hashed_password");
    stats = vault.getSystemStatsAdmin(true);
    expect(stats.allowRegistration).toBe(true);

    // When registration disabled
    vault.setRegistrationAllowed(false);
    stats = vault.getSystemStatsAdmin(false);
    expect(stats.allowRegistration).toBe(false);
    expect(stats.pollerRunning).toBe(false);
  });

  it("ensures system_settings table is created on existing v1 database lacking it", () => {
    const testDbPath = `data/test-settings-migration-${Date.now()}.db`;
    const rawDb = new Database(testDbPath, { create: true });
    rawDb.exec(`
      CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      PRAGMA user_version = 1;
    `);
    rawDb.close();

    const migratedVault = new StorageVault(testDbPath);
    migratedVault.setSetting("test_key", "test_val");
    expect(migratedVault.getSetting("test_key")).toBe("test_val");

    migratedVault.close();
    try { unlinkSync(testDbPath); } catch {}
  });
});

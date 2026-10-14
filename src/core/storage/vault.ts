import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret } from "../crypto";
import type {
  AdminSystemStats,
  AdminUserView,
  CredentialRef,
  CardAccent,
  InputCredential,
  Invitation,
  InvitationStatus,
  InvitationView,
  Session,
  StoredCredential,
  UsageReport,
  User,
  UserRole,
} from "../../types";

const CARD_ACCENTS: Record<string, true> = {
  default: true,
  amber: true,
  emerald: true,
  cyan: true,
  violet: true,
  slate: true,
};

interface CredentialRow {
  id: string;
  owner_id: string | null;
  provider: string;
  account_label: string;
  accent: string | null;
  credential_type: string;
  encrypted_secret: string;
  iv: string;
  tag: string;
  metadata: string | null;
  created_at: number;
  updated_at: number;
}
interface CredentialRefRow {
  id: string;
  owner_id: string | null;
  provider: string;
  account_label: string;
}

function rowToCredentialRef(row: CredentialRefRow): CredentialRef {
  return {
    id: row.id,
    ownerId: row.owner_id ?? "",
    provider: row.provider,
    accountLabel: row.account_label,
  };
}
const CREDENTIAL_METADATA_ENCRYPTION_ENV = "CREDENTIAL_METADATA_ENCRYPTION";
const ENCRYPTED_METADATA_VERSION = 1;

interface DecodedCredentialMetadata {
  metadata: Record<string, unknown>;
  encrypted: boolean;
}

function parseMetadataRecord(value: unknown, message: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as Record<string, unknown>;
}

function decodeCredentialMetadata(serialized: string): DecodedCredentialMetadata {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("Credential metadata is malformed.");
  }

  const record = parseMetadataRecord(parsed, "Credential metadata is malformed.");

  if (Object.prototype.hasOwnProperty.call(record, "$vault")) {
    const keys = Object.keys(record);
    const ciphertext = record["ciphertext"];
    const iv = record["iv"];
    const tag = record["tag"];
    if (
      record["$vault"] !== ENCRYPTED_METADATA_VERSION ||
      keys.length !== 4 ||
      !keys.includes("ciphertext") ||
      !keys.includes("iv") ||
      !keys.includes("tag") ||
      typeof ciphertext !== "string" ||
      !/^(?:[0-9a-f]{2})*$/i.test(ciphertext) ||
      typeof iv !== "string" ||
      !/^[0-9a-f]{24}$/i.test(iv) ||
      typeof tag !== "string" ||
      !/^[0-9a-f]{32}$/i.test(tag)
    ) {
      throw new Error("Credential metadata envelope is invalid.");
    }

    let plaintext: string;
    try {
      plaintext = decryptSecret({ ciphertext, iv, tag });
    } catch {
      throw new Error("Credential metadata decryption failed.");
    }
    let metadata: unknown;
    try {
      metadata = JSON.parse(plaintext);
    } catch {
      throw new Error("Credential metadata is malformed.");
    }
    return {
      metadata: parseMetadataRecord(metadata, "Credential metadata is malformed."),
      encrypted: true,
    };
  }

  return { metadata: record, encrypted: false };
}

function serializeCredentialMetadata(
  metadata: Record<string, unknown> | undefined,
  encrypt: boolean,
): string | null {
  if (metadata === undefined) return null;
  if (Object.prototype.hasOwnProperty.call(metadata, "$vault")) {
    throw new Error('Credential metadata cannot use the reserved "$vault" field.');
  }
  const plaintext = JSON.stringify(metadata);
  if (typeof plaintext !== "string") throw new Error("Credential metadata is not serializable.");
  if (!encrypt) return plaintext;

  const payload = encryptSecret(plaintext);
  return JSON.stringify({
    $vault: ENCRYPTED_METADATA_VERSION,
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    tag: payload.tag,
  });
}

interface InvitationRow {
  id: string;
  email: string;
  token_hash: string;
  created_by: string;
  expires_at: number;
  accepted_at: number | null;
  revoked_at: number | null;
  created_at: number;
}

function computeInvitationStatus(
  row: { expires_at: number; accepted_at: number | null; revoked_at: number | null },
  now: number = Date.now(),
): InvitationStatus {
  if (row.accepted_at !== null) return "accepted";
  if (row.revoked_at !== null) return "revoked";
  if (row.expires_at <= now) return "expired";
  return "pending";
}

export class StorageVault {
  readonly #db: Database;
  #closed = false;
  #metadataEncryptionEnabled =
    process.env[CREDENTIAL_METADATA_ENCRYPTION_ENV]?.trim().toLowerCase() === "enabled";
  #schemaVersion = 0;

  constructor(dbPath: string = "data/usage.db") {
    const dir = dbPath.includes("/") ? dbPath.slice(0, dbPath.lastIndexOf("/")) : "";
    if (dir) {
      try {
        const fs = require("node:fs");
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      } catch {}
    }

    this.#db = new Database(dbPath, { create: true });
    try {
      this.#initPragmas();
      this.#migrate();
      this.#verifyMasterKeyCredentials();
    } catch (error) {
      this.#closed = true;
      try {
        this.#db.close();
      } catch {}
      throw error;
    }
  }

  #initPragmas(): void {
    this.#db.exec("PRAGMA journal_mode = WAL;");
    this.#db.exec("PRAGMA synchronous = NORMAL;");
    this.#db.exec("PRAGMA foreign_keys = ON;");
    this.#db.exec("PRAGMA busy_timeout = 5000;");
  }

  #migrate(): void {
    const versionRow = this.#db.prepare("PRAGMA user_version;").get() as { user_version: number } | undefined;
    let currentVersion = versionRow?.user_version ?? 0;

    if (currentVersion < 1) {
      this.#db.transaction(() => {
        this.#db.exec(`
          CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          );
          CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

          CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
          CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

          CREATE TABLE IF NOT EXISTS credentials (
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

          CREATE TABLE IF NOT EXISTS usage_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            credential_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            account_label TEXT NOT NULL,
            report_json TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
          );

          CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
          );
        `);

        // Check if existing tables lack columns added in v1
        const credCols = this.#db.prepare("PRAGMA table_info(credentials)").all() as { name: string }[];
        if (!credCols.some(c => c.name === "owner_id")) {
          this.#db.exec("ALTER TABLE credentials ADD COLUMN owner_id TEXT REFERENCES users(id) ON DELETE CASCADE;");
        }
        if (!credCols.some(c => c.name === "accent")) {
          this.#db.exec("ALTER TABLE credentials ADD COLUMN accent TEXT NOT NULL DEFAULT 'default';");
        }

        const snapCols = this.#db.prepare("PRAGMA table_info(usage_snapshots)").all() as { name: string }[];
        if (!snapCols.some(c => c.name === "owner_id")) {
          this.#db.exec("ALTER TABLE usage_snapshots ADD COLUMN owner_id TEXT REFERENCES users(id) ON DELETE CASCADE;");
        }

        const userCols = this.#db.prepare("PRAGMA table_info(users)").all() as { name: string }[];
        if (!userCols.some(c => c.name === "role")) {
          this.#db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';");
          this.#db.exec("UPDATE users SET role = 'admin' WHERE id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1);");
        }

        this.#db.exec(`
          CREATE INDEX IF NOT EXISTS idx_credentials_owner_id ON credentials(owner_id);
          CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_owner_prov_label ON credentials(owner_id, provider, account_label);
          CREATE INDEX IF NOT EXISTS idx_snapshots_cred_time ON usage_snapshots(credential_id, fetched_at DESC);
          CREATE INDEX IF NOT EXISTS idx_snapshots_owner_time ON usage_snapshots(owner_id, fetched_at DESC);
          CREATE INDEX IF NOT EXISTS idx_snapshots_owner_cred_time ON usage_snapshots(owner_id, credential_id, fetched_at DESC);
          PRAGMA user_version = 1;
        `);
      })();
      currentVersion = 1;
    }

    // Ensure role column exists even on databases migrated prior to role introduction
    const userCols = this.#db.prepare("PRAGMA table_info(users)").all() as { name: string }[];
    if (userCols.length > 0 && !userCols.some(c => c.name === "role")) {
      this.#db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';");
    }

    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL COLLATE NOCASE,
        token_hash TEXT NOT NULL UNIQUE,
        created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL,
        accepted_at INTEGER,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);
      CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email COLLATE NOCASE);
      CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON invitations(created_by);
    `);
    if (this.#metadataEncryptionEnabled && currentVersion < 2) {
      this.#migrateCredentialMetadataToV2();
      currentVersion = 2;
    }

    this.#schemaVersion = currentVersion;
  }

  #verifyMasterKeyCredentials(): void {
    const tableExists = this.#db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credentials'"
    ).get();
    if (!tableExists) return;

    const rows = this.#db.prepare(
      "SELECT encrypted_secret, iv, tag, metadata FROM credentials"
    ).all() as { encrypted_secret: string; iv: string; tag: string; metadata: string | null }[];

    for (const row of rows) {
      try {
        decryptSecret({ ciphertext: row.encrypted_secret, iv: row.iv, tag: row.tag });
      } catch {
        throw new Error("Credential decryption failed.");
      }
      if (row.metadata !== null) {
        decodeCredentialMetadata(row.metadata);
      }
    }
  }

  getSchemaVersion(): number {
    return this.#schemaVersion;
  }

  #shouldEncryptMetadata(): boolean {
    return this.#metadataEncryptionEnabled || this.#schemaVersion >= 2;
  }
  #withMetadataWrite<T>(write: () => T): T {
    const tx = this.#db.transaction(() => {
      if (this.#schemaVersion < 2) {
        const versionRow = this.#db.prepare("PRAGMA user_version;").get() as { user_version: number } | undefined;
        if ((versionRow?.user_version ?? 0) >= 2) {
          this.#schemaVersion = 2;
        }
      }
      return write();
    });
    return tx.immediate();
  }


  #ensureMetadataEncryptionVersion(): void {
    if (this.#metadataEncryptionEnabled && this.#schemaVersion < 2) {
      this.#migrateCredentialMetadataToV2();
    }
  }

  migrateCredentialMetadata(): void {
    if (this.#closed) throw new Error("Vault is closed.");
    if (this.#schemaVersion >= 2) return;
    this.#migrateCredentialMetadataToV2();
  }

  #migrateCredentialMetadataToV2(): void {
    const tx = this.#db.transaction(() => {
      const versionRow = this.#db.prepare("PRAGMA user_version;").get() as { user_version: number } | undefined;
      if ((versionRow?.user_version ?? 0) >= 2) {
        return;
      }

      const tableExists = this.#db.prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credentials'"
      ).get();
      if (!tableExists) {
        throw new Error("Credential table missing.");
      }

      const rows = this.#db.prepare(
        "SELECT id, encrypted_secret, iv, tag, metadata FROM credentials"
      ).all() as { id: string; encrypted_secret: string; iv: string; tag: string; metadata: string | null }[];
      const updates: { id: string; encryptedJson: string }[] = [];
      for (const row of rows) {
        try {
          decryptSecret({ ciphertext: row.encrypted_secret, iv: row.iv, tag: row.tag });
        } catch {
          throw new Error("Credential decryption failed.");
        }
        if (row.metadata !== null) {
          const decoded = decodeCredentialMetadata(row.metadata);
          if (!decoded.encrypted) {
            const encryptedJson = serializeCredentialMetadata(decoded.metadata, true);
            if (!encryptedJson) throw new Error("Metadata encryption failed.");
            updates.push({ id: row.id, encryptedJson });
          }
        }
      }

      const updateStmt = this.#db.prepare("UPDATE credentials SET metadata = ? WHERE id = ?");
      for (const update of updates) {
        updateStmt.run(update.encryptedJson, update.id);
      }
      this.#db.exec("PRAGMA user_version = 2;");
    });
    tx.immediate();
    this.#schemaVersion = 2;
  }

  // ==================== User Management ====================

  createUser(email: string, passwordHash: string): User {
    const result = this.createUserWithLegacyClaim(email, passwordHash);
    return result.user;
  }

  createUserWithLegacyClaim(
    email: string,
    passwordHash: string,
  ): { user: User; claimedLegacy: boolean } {
    const id = randomUUID();
    const now = Date.now();
    const normalizedEmail = email.trim().toLowerCase();

    const tx = this.#db.transaction(() => {
      const countRow = this.#db
        .prepare("SELECT COUNT(*) as count FROM users")
        .get() as { count: number };
      const isFirstUser = countRow.count === 0;
      const role: UserRole = isFirstUser ? "admin" : "user";

      this.#db
        .prepare(`
        INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
        .run(id, normalizedEmail, passwordHash, role, now, now);

      let claimedLegacy = false;
      if (isFirstUser) {
        const legacyCreds = this.#db.prepare(`
          SELECT id, provider, account_label, created_at
          FROM credentials
          WHERE owner_id IS NULL
          ORDER BY provider ASC, account_label ASC, created_at ASC, id ASC
        `).all() as { id: string; provider: string; account_label: string; created_at: number }[];

        if (legacyCreds.length > 0) {
          const allExistingLabels = new Set<string>();
          for (const cred of legacyCreds) {
            allExistingLabels.add(`${cred.provider.toLowerCase()}::${cred.account_label}`);
          }

          const seenBaseLabels = new Set<string>();

          for (const cred of legacyCreds) {
            const providerKey = cred.provider.toLowerCase();
            const baseKey = `${providerKey}::${cred.account_label}`;

            if (!seenBaseLabels.has(baseKey)) {
              seenBaseLabels.add(baseKey);
            } else {
              let counter = 2;
              let candidateLabel = `${cred.account_label} (${counter})`;
              while (allExistingLabels.has(`${providerKey}::${candidateLabel}`)) {
                counter++;
                candidateLabel = `${cred.account_label} (${counter})`;
              }

              allExistingLabels.add(`${providerKey}::${candidateLabel}`);

              this.#db.prepare(`
                UPDATE credentials
                SET account_label = ?, updated_at = ?
                WHERE id = ?
              `).run(candidateLabel, now, cred.id);

              this.#db.prepare(`
                UPDATE usage_snapshots
                SET account_label = ?
                WHERE credential_id = ?
              `).run(candidateLabel, cred.id);

              const snaps = this.#db.prepare(`
                SELECT id, report_json FROM usage_snapshots WHERE credential_id = ?
              `).all(cred.id) as { id: number; report_json: string }[];

              for (const snap of snaps) {
                try {
                  const parsed = JSON.parse(snap.report_json);
                  parsed.accountLabel = candidateLabel;
                  this.#db.prepare(`
                    UPDATE usage_snapshots SET report_json = ? WHERE id = ?
                  `).run(JSON.stringify(parsed), snap.id);
                } catch {}
              }
            }
          }
        }

        this.#db
          .prepare("UPDATE credentials SET owner_id = ? WHERE owner_id IS NULL")
          .run(id);
        this.#db
          .prepare("UPDATE usage_snapshots SET owner_id = ? WHERE owner_id IS NULL")
          .run(id);
        claimedLegacy = true;
      }

      return {
        user: {
          id,
          email: normalizedEmail,
          role,
          createdAt: now,
          updatedAt: now,
        },
        claimedLegacy,
      };
    });

    return tx.immediate();
  }

  getUserByEmail(email: string): (User & { passwordHash: string }) | null {
    const normalizedEmail = email.trim().toLowerCase();
    const row = this.#db.prepare(`
      SELECT id, email, password_hash, role, created_at, updated_at
      FROM users WHERE email = ?
    `).get(normalizedEmail) as { id: string; email: string; password_hash: string; role: string; created_at: number; updated_at: number } | undefined;

    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      role: (row.role as UserRole) || "user",
      passwordHash: row.password_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  getUserById(id: string): User | null {
    const row = this.#db.prepare(`
      SELECT id, email, role, created_at, updated_at
      FROM users WHERE id = ?
    `).get(id) as { id: string; email: string; role: string; created_at: number; updated_at: number } | undefined;

    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      role: (row.role as UserRole) || "user",
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }


  getUserCount(): number {
    const row = this.#db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
    return row.count;
  }

  // ==================== Admin Operations ====================

  listUsersAdmin(): AdminUserView[] {
    const now = Date.now();
    interface AdminUserRow {
      id: string;
      email: string;
      role: string;
      created_at: number;
      updated_at: number;
      credential_count: number;
      active_session_count: number;
    }

    const rows = this.#db.prepare(`
      SELECT
        u.id,
        u.email,
        u.role,
        u.created_at,
        u.updated_at,
        (SELECT COUNT(*) FROM credentials c WHERE c.owner_id = u.id) as credential_count,
        (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ?) as active_session_count
      FROM users u
      ORDER BY u.created_at ASC
    `).all(now) as AdminUserRow[];

    return rows.map((r) => ({
      id: r.id,
      email: r.email,
      role: (r.role as UserRole) || "user",
      createdAt: r.created_at,
      updatedAt: r.updated_at,
      credentialCount: r.credential_count,
      activeSessionCount: r.active_session_count,
    }));
  }

  updateUserRoleAdmin(
    adminUserId: string,
    targetUserId: string,
    newRole: UserRole,
  ): { success: boolean; error?: string } {
    if (this.#closed) return { success: false, error: "Database is closed" };

    const admin = this.getUserById(adminUserId);
    if (!admin || admin.role !== "admin") {
      return { success: false, error: "Unauthorized" };
    }

    const target = this.getUserById(targetUserId);
    if (!target) {
      return { success: false, error: "User not found" };
    }

    if (target.role === "admin" && newRole !== "admin") {
      const adminCountRow = this.#db
        .prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
        .get() as { count: number };
      if (adminCountRow.count <= 1) {
        return { success: false, error: "Cannot demote the last admin" };
      }
    }

    const now = Date.now();
    this.#db
      .prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?")
      .run(newRole, now, targetUserId);

    return { success: true };
  }

  deleteUserAdmin(
    adminUserId: string,
    targetUserId: string,
  ): { success: boolean; error?: string } {
    if (this.#closed) return { success: false, error: "Database is closed" };

    const admin = this.getUserById(adminUserId);
    if (!admin || admin.role !== "admin") {
      return { success: false, error: "Unauthorized" };
    }

    if (adminUserId === targetUserId) {
      return { success: false, error: "Cannot delete your own account" };
    }

    const target = this.getUserById(targetUserId);
    if (!target) {
      return { success: false, error: "User not found" };
    }

    if (target.role === "admin") {
      const adminCountRow = this.#db
        .prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
        .get() as { count: number };
      if (adminCountRow.count <= 1) {
        return { success: false, error: "Cannot delete the last admin" };
      }
    }

    this.#db.prepare("DELETE FROM users WHERE id = ?").run(targetUserId);

    return { success: true };
  }

  getSystemStatsAdmin(pollerRunning: boolean): AdminSystemStats {
    const now = Date.now();

    const userCountRow = this.#db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
    const credCountRow = this.#db.prepare("SELECT COUNT(*) as count FROM credentials").get() as { count: number };
    const snapCountRow = this.#db.prepare("SELECT COUNT(*) as count FROM usage_snapshots").get() as { count: number };
    const sessionCountRow = this.#db.prepare("SELECT COUNT(*) as count FROM sessions WHERE expires_at > ?").get(now) as { count: number };

    const pageCountRow = this.#db.prepare("PRAGMA page_count;").get() as { page_count: number } | undefined;
    const pageSizeRow = this.#db.prepare("PRAGMA page_size;").get() as { page_size: number } | undefined;
    const databaseSizeBytes = (pageCountRow?.page_count ?? 0) * (pageSizeRow?.page_size ?? 0);

    const integrity = this.checkIntegrity();

    const providerRows = this.#db.prepare(`
      SELECT provider, COUNT(*) as count FROM credentials GROUP BY provider
    `).all() as { provider: string; count: number }[];
    const providerCounts: Record<string, number> = {};
    for (const row of providerRows) {
      providerCounts[row.provider] = row.count;
    }

    return {
      totalUsers: userCountRow.count,
      totalCredentials: credCountRow.count,
      totalSnapshots: snapCountRow.count,
      activeSessions: sessionCountRow.count,
      pollerRunning,
      allowRegistration: this.isRegistrationAllowed(),
      databaseSizeBytes,
      integrity,
      providerCounts,
    };
  }

  // ==================== System Settings & Policies ====================

  getSetting(key: string, defaultValue: string = ""): string {
    const row = this.#db.prepare("SELECT value FROM system_settings WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row ? row.value : defaultValue;
  }

  setSetting(key: string, value: string): void {
    const now = Date.now();
    this.#db.prepare(`
      INSERT INTO system_settings (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).run(key, value, now);
  }

  isRegistrationAllowed(): boolean {
    if (this.getUserCount() === 0) {
      return true;
    }
    const val = this.getSetting("allow_registration", "true");
    return val !== "false";
  }

  setRegistrationAllowed(allowed: boolean): void {
    this.setSetting("allow_registration", allowed ? "true" : "false");
  }
  // ==================== Invitation Management ====================

  createInvitation(input: {
    email: string;
    tokenHash: string;
    createdBy: string;
    expiresAt: number;
    createdAt?: number;
  }): Invitation {
    if (this.#closed) throw new Error("Database is closed");
    const creator = this.getUserById(input.createdBy);
    if (!creator || creator.role !== "admin") {
      throw new Error("Unauthorized: Only administrators can create invitations");
    }

    const id = randomUUID();
    const now = input.createdAt ?? Date.now();
    const normalizedEmail = input.email.trim().toLowerCase();

    this.#db
      .prepare(`
        INSERT INTO invitations (id, email, token_hash, created_by, expires_at, accepted_at, revoked_at, created_at)
        VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)
      `)
      .run(id, normalizedEmail, input.tokenHash, input.createdBy, input.expiresAt, now);

    return {
      id,
      email: normalizedEmail,
      tokenHash: input.tokenHash,
      createdBy: input.createdBy,
      expiresAt: input.expiresAt,
      acceptedAt: null,
      revokedAt: null,
      createdAt: now,
    };
  }

  listInvitations(adminId: string): InvitationView[] {
    if (this.#closed) throw new Error("Database is closed");
    const admin = this.getUserById(adminId);
    if (!admin || admin.role !== "admin") {
      throw new Error("Unauthorized: Only administrators can view invitations");
    }

    const rows = this.#db
      .prepare(`
        SELECT id, email, created_by, expires_at, accepted_at, revoked_at, created_at
        FROM invitations
        ORDER BY created_at DESC
      `)
      .all() as Array<{
        id: string;
        email: string;
        created_by: string;
        expires_at: number;
        accepted_at: number | null;
        revoked_at: number | null;
        created_at: number;
      }>;

    const now = Date.now();
    return rows.map((r) => ({
      id: r.id,
      email: r.email,
      createdBy: r.created_by,
      status: computeInvitationStatus(r, now),
      expiresAt: r.expires_at,
      acceptedAt: r.accepted_at,
      revokedAt: r.revoked_at,
      createdAt: r.created_at,
    }));
  }

  revokeInvitation(adminId: string, invitationId: string): boolean {
    if (this.#closed) throw new Error("Database is closed");
    const admin = this.getUserById(adminId);
    if (!admin || admin.role !== "admin") {
      throw new Error("Unauthorized: Only administrators can revoke invitations");
    }

    const now = Date.now();
    const res = this.#db
      .prepare(`
        UPDATE invitations
        SET revoked_at = ?
        WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL
      `)
      .run(now, invitationId);

    return res.changes > 0;
  }

  getInvitationByTokenHash(tokenHash: string): Invitation | null {
    if (this.#closed) return null;
    const row = this.#db
      .prepare(`
        SELECT id, email, token_hash, created_by, expires_at, accepted_at, revoked_at, created_at
        FROM invitations
        WHERE token_hash = ?
      `)
      .get(tokenHash) as InvitationRow | undefined;

    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      tokenHash: row.token_hash,
      createdBy: row.created_by,
      expiresAt: row.expires_at,
      acceptedAt: row.accepted_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
    };
  }

  getInvitationById(id: string): Invitation | null {
    if (this.#closed) return null;
    const row = this.#db
      .prepare(`
        SELECT id, email, token_hash, created_by, expires_at, accepted_at, revoked_at, created_at
        FROM invitations
        WHERE id = ?
      `)
      .get(id) as InvitationRow | undefined;

    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      tokenHash: row.token_hash,
      createdBy: row.created_by,
      expiresAt: row.expires_at,
      acceptedAt: row.accepted_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
    };
  }

  acceptInvitationAtomic(
    tokenHash: string,
    userToCreate: {
      id?: string;
      passwordHash: string;
      createdAt?: number;
      updatedAt?: number;
    },
  ): { user: User; invitation: Invitation } {
    if (this.#closed) throw new Error("Database is closed");

    const tx = this.#db.transaction(() => {
      const now = Date.now();
      const row = this.#db
        .prepare(`
          SELECT id, email, token_hash, created_by, expires_at, accepted_at, revoked_at, created_at
          FROM invitations
          WHERE token_hash = ?
        `)
        .get(tokenHash) as InvitationRow | undefined;

      if (!row) {
        throw new Error("INVALID_INVITATION");
      }

      if (row.revoked_at !== null) {
        throw new Error("INVITATION_REVOKED");
      }

      if (row.accepted_at !== null) {
        throw new Error("INVITATION_USED");
      }

      if (row.expires_at <= now) {
        throw new Error("INVITATION_EXPIRED");
      }

      const existingUser = this.#db
        .prepare("SELECT id FROM users WHERE email = ?")
        .get(row.email);
      if (existingUser) {
        throw new Error("EMAIL_EXISTS");
      }

      const userId = userToCreate.id || randomUUID();
      const userCreated = userToCreate.createdAt || now;
      const userUpdated = userToCreate.updatedAt || now;

      // Note: Invitation accepted user ALWAYS receives role "user", NEVER "admin",
      // and NEVER claims unowned legacy credentials/snapshots.
      this.#db
        .prepare(`
          INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
          VALUES (?, ?, ?, 'user', ?, ?)
        `)
        .run(userId, row.email, userToCreate.passwordHash, userCreated, userUpdated);

      const updateRes = this.#db
        .prepare(`
          UPDATE invitations
          SET accepted_at = ?
          WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL
        `)
        .run(now, row.id);

      if (updateRes.changes === 0) {
        throw new Error("INVITATION_USED");
      }

      const user: User = {
        id: userId,
        email: row.email,
        role: "user",
        createdAt: userCreated,
        updatedAt: userUpdated,
      };

      const updatedInvitation: Invitation = {
        id: row.id,
        email: row.email,
        tokenHash: row.token_hash,
        createdBy: row.created_by,
        expiresAt: row.expires_at,
        acceptedAt: now,
        revokedAt: null,
        createdAt: row.created_at,
      };

      return { user, invitation: updatedInvitation };
    });

    return tx.immediate();
  }

  // ==================== Session Management ====================

  createSession(userId: string, tokenHash: string, expiresAt: number): Session {
    const id = randomUUID();
    const now = Date.now();
    this.#db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, userId, tokenHash, expiresAt, now);

    return {
      id,
      userId,
      tokenHash,
      expiresAt,
      createdAt: now,
    };
  }

  getSessionByTokenHash(tokenHash: string): (Session & { user: User }) | null {
    interface SessionUserRow {
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: number;
      created_at: number;
      email: string;
      role: string;
      user_created_at: number;
      user_updated_at: number;
    }

    const row = this.#db.prepare(`
      SELECT
        s.id, s.user_id, s.token_hash, s.expires_at, s.created_at,
        u.email, u.role, u.created_at as user_created_at, u.updated_at as user_updated_at
      FROM sessions s
      INNER JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ?
    `).get(tokenHash) as SessionUserRow | undefined;

    if (!row) return null;
    return {
      id: row.id,
      userId: row.user_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      user: {
        id: row.user_id,
        email: row.email,
        role: (row.role as UserRole) || "user",
        createdAt: row.user_created_at,
        updatedAt: row.user_updated_at,
      },
    };
  }

  deleteSessionByTokenHash(tokenHash: string): boolean {
    if (this.#closed) return false;
    const res = this.#db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    return res.changes > 0;
  }

  deleteExpiredSessions(now: number = Date.now()): number {
    if (this.#closed) return 0;
    const res = this.#db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now);
    return res.changes;
  }

  // ==================== Credential Management ====================

  saveCredential(ownerId: string, input: InputCredential): StoredCredential {
    if (this.#closed) throw new Error("Vault is closed.");
    this.#ensureMetadataEncryptionVersion();
    const provider = input.provider.toLowerCase();
    const accent = input.accent && CARD_ACCENTS[input.accent] ? input.accent : "default";
    const now = Date.now();
    const enc = encryptSecret(input.secret);
    return this.#withMetadataWrite(() => {
      const metadataSerialized = serializeCredentialMetadata(input.metadata, this.#shouldEncryptMetadata());
      const existing = this.#db.prepare(
        "SELECT id, created_at FROM credentials WHERE owner_id = ? AND provider = ? AND account_label = ?",
      ).get(ownerId, provider, input.accountLabel) as { id: string; created_at: number } | undefined;
      if (existing) {
        this.#db.prepare(`
          UPDATE credentials SET accent = ?, credential_type = ?, encrypted_secret = ?, iv = ?, tag = ?, metadata = ?, updated_at = ?
          WHERE owner_id = ? AND id = ?
        `).run(accent, input.credentialType, enc.ciphertext, enc.iv, enc.tag, metadataSerialized, now, ownerId, existing.id);
        return {
          id: existing.id, ownerId, provider, accountLabel: input.accountLabel, accent,
          credentialType: input.credentialType, secret: input.secret, metadata: input.metadata,
          createdAt: existing.created_at, updatedAt: now,
        };
      }
      const id = randomUUID();
      this.#db.prepare(`
        INSERT INTO credentials (id, owner_id, provider, account_label, accent, credential_type, encrypted_secret, iv, tag, metadata, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, ownerId, provider, input.accountLabel, accent, input.credentialType, enc.ciphertext, enc.iv, enc.tag, metadataSerialized, now, now);
      return {
        id, ownerId, provider, accountLabel: input.accountLabel, accent,
        credentialType: input.credentialType, secret: input.secret, metadata: input.metadata,
        createdAt: now, updatedAt: now,
      };
    });
  }

  saveCredentialInternal(input: InputCredential): StoredCredential {
    if (this.#closed) throw new Error("Vault is closed.");
    this.#ensureMetadataEncryptionVersion();
    const provider = input.provider.toLowerCase();
    const accent = input.accent && CARD_ACCENTS[input.accent] ? input.accent : "default";
    const now = Date.now();
    const enc = encryptSecret(input.secret);
    return this.#withMetadataWrite(() => {
      const metadataSerialized = serializeCredentialMetadata(input.metadata, this.#shouldEncryptMetadata());
      const existing = this.#db.prepare(
        "SELECT id, created_at FROM credentials WHERE owner_id IS NULL AND provider = ? AND account_label = ?",
      ).get(provider, input.accountLabel) as { id: string; created_at: number } | undefined;
      if (existing) {
        this.#db.prepare(`
          UPDATE credentials SET accent = ?, credential_type = ?, encrypted_secret = ?, iv = ?, tag = ?, metadata = ?, updated_at = ?
          WHERE owner_id IS NULL AND id = ?
        `).run(accent, input.credentialType, enc.ciphertext, enc.iv, enc.tag, metadataSerialized, now, existing.id);
        return {
          id: existing.id, ownerId: undefined as unknown as string, provider, accountLabel: input.accountLabel, accent,
          credentialType: input.credentialType, secret: input.secret, metadata: input.metadata,
          createdAt: existing.created_at, updatedAt: now,
        };
      }
      const id = randomUUID();
      this.#db.prepare(`
        INSERT INTO credentials (id, owner_id, provider, account_label, accent, credential_type, encrypted_secret, iv, tag, metadata, created_at, updated_at)
        VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, provider, input.accountLabel, accent, input.credentialType, enc.ciphertext, enc.iv, enc.tag, metadataSerialized, now, now);
      return {
        id, ownerId: undefined as unknown as string, provider, accountLabel: input.accountLabel, accent,
        credentialType: input.credentialType, secret: input.secret, metadata: input.metadata,
        createdAt: now, updatedAt: now,
      };
    });
  }
  listCredentials(ownerId: string, provider?: string): StoredCredential[] {
    const query = provider
      ? this.#db.prepare("SELECT * FROM credentials WHERE owner_id = ? AND provider = ? ORDER BY created_at ASC")
      : this.#db.prepare("SELECT * FROM credentials WHERE owner_id = ? ORDER BY provider ASC, created_at ASC");
    const rows = (provider ? query.all(ownerId, provider.toLowerCase()) : query.all(ownerId)) as CredentialRow[];
    return rows.map(row => this.#rowToStoredCredential(row));
  }

  /**
   * Explicit internal lightweight enumeration across all owners for the background daemon.
   * It deliberately reads neither ciphertext nor metadata, avoiding bulk decryption during sweep setup.
   */
  listAllCredentialRefsInternal(): CredentialRef[] {
    const rows = this.#db.prepare(
      "SELECT id, owner_id, provider, account_label FROM credentials ORDER BY provider ASC, created_at ASC",
    ).all() as CredentialRefRow[];
    return rows.map(rowToCredentialRef);
  }

  listCredentialRefs(ownerId: string): CredentialRef[] {
    if (!ownerId) return [];
    const rows = this.#db.prepare(
      "SELECT id, owner_id, provider, account_label FROM credentials WHERE owner_id = ? ORDER BY provider ASC, created_at ASC",
    ).all(ownerId) as CredentialRefRow[];
    return rows.map(rowToCredentialRef);
  }

  getCredentialRef(ownerId: string, id: string): CredentialRef | null {
    if (!ownerId) return null;
    const row = this.#db.prepare(
      "SELECT id, owner_id, provider, account_label FROM credentials WHERE owner_id = ? AND id = ?",
    ).get(ownerId, id) as CredentialRefRow | undefined;
    return row ? rowToCredentialRef(row) : null;
  }
  /** Rechecks current ownership without decrypting the credential secret. */
  getCredentialRefInternal(id: string): CredentialRef | null {
    const row = this.#db.prepare(
      "SELECT id, owner_id, provider, account_label FROM credentials WHERE id = ?",
    ).get(id) as CredentialRefRow | undefined;
    return row ? rowToCredentialRef(row) : null;
  }


  /**
   * Explicit internal enumeration across all owners for the background daemon.
   */
  listAllCredentialsInternal(): StoredCredential[] {
    const rows = this.#db.prepare("SELECT * FROM credentials ORDER BY provider ASC, created_at ASC").all() as CredentialRow[];
    return rows.map(row => this.#rowToStoredCredential(row));
  }

  getCredential(ownerId: string, id: string): StoredCredential | null {
    if (!ownerId) return this.getCredentialInternal(id);
    const row = this.#db.prepare("SELECT * FROM credentials WHERE owner_id = ? AND id = ?").get(ownerId, id) as CredentialRow | undefined;
    return row ? this.#rowToStoredCredential(row) : null;
  }

  getCredentialInternal(id: string): StoredCredential | null {
    const row = this.#db.prepare("SELECT * FROM credentials WHERE id = ?").get(id) as CredentialRow | undefined;
    return row ? this.#rowToStoredCredential(row) : null;
  }

  deleteCredential(ownerId: string, id: string): boolean {
    if (this.#closed) return false;
    if (!ownerId) return this.#db.prepare("DELETE FROM credentials WHERE id = ?").run(id).changes > 0;
    return this.#db.prepare("DELETE FROM credentials WHERE owner_id = ? AND id = ?").run(ownerId, id).changes > 0;
  }

  deleteCredentialInternal(id: string): boolean {
    if (this.#closed) return false;
    return this.#db.prepare("DELETE FROM credentials WHERE id = ?").run(id).changes > 0;
  }

  updateCredential(ownerId: string, id: string, changes: { accountLabel?: string; accent?: CardAccent | string | null }): boolean {
    if (this.#closed) return false;
    if (!ownerId) return this.updateCredentialInternal(id, changes);
    const current = this.#db.prepare("SELECT provider, account_label, accent FROM credentials WHERE owner_id = ? AND id = ?")
      .get(ownerId, id) as { provider: string; account_label: string; accent: string } | undefined;
    if (!current) return false;
    const label = changes.accountLabel?.trim();
    if (changes.accountLabel !== undefined && !label) return false;
    const accent = changes.accent === null || changes.accent === "" ? "default" : changes.accent;
    if (accent !== undefined && !CARD_ACCENTS[accent]) return false;
    const nextLabel = label ?? current.account_label;
    if (nextLabel !== current.account_label && this.#db.prepare(
      "SELECT 1 FROM credentials WHERE owner_id = ? AND provider = ? AND account_label = ? AND id != ? LIMIT 1",
    ).get(ownerId, current.provider, nextLabel, id)) return false;
    const result = this.#db.prepare(
      "UPDATE credentials SET account_label = ?, accent = ?, updated_at = ? WHERE owner_id = ? AND id = ?",
    ).run(nextLabel, accent ?? current.accent, Date.now(), ownerId, id);
    if (result.changes === 0) return false;
    this.#db.prepare("UPDATE usage_snapshots SET account_label = ? WHERE owner_id = ? AND credential_id = ?")
      .run(nextLabel, ownerId, id);
    return true;
  }

  updateCredentialInternal(id: string, changes: { accountLabel?: string; accent?: CardAccent | string | null }): boolean {
    if (this.#closed) return false;
    const current = this.#db.prepare("SELECT owner_id, provider, account_label, accent FROM credentials WHERE id = ?")
      .get(id) as { owner_id: string | null; provider: string; account_label: string; accent: string } | undefined;
    if (!current) return false;
    const label = changes.accountLabel?.trim();
    if (changes.accountLabel !== undefined && !label) return false;
    const accent = changes.accent === null || changes.accent === "" ? "default" : changes.accent;
    if (accent !== undefined && !CARD_ACCENTS[accent]) return false;
    const nextLabel = label ?? current.account_label;
    if (nextLabel !== current.account_label) {
      const collision = current.owner_id !== null
        ? this.#db.prepare("SELECT 1 FROM credentials WHERE owner_id = ? AND provider = ? AND account_label = ? AND id != ? LIMIT 1").get(current.owner_id, current.provider, nextLabel, id)
        : this.#db.prepare("SELECT 1 FROM credentials WHERE owner_id IS NULL AND provider = ? AND account_label = ? AND id != ? LIMIT 1").get(current.provider, nextLabel, id);
      if (collision) return false;
    }
    const result = this.#db.prepare(
      "UPDATE credentials SET account_label = ?, accent = ?, updated_at = ? WHERE id = ?",
    ).run(nextLabel, accent ?? current.accent, Date.now(), id);
    if (result.changes === 0) return false;
    this.#db.prepare("UPDATE usage_snapshots SET account_label = ? WHERE credential_id = ?")
      .run(nextLabel, id);
    return true;
  }

  updateCredentialLabel(ownerId: string, id: string, newLabel: string): boolean {
    return this.updateCredential(ownerId, id, { accountLabel: newLabel });
  }

  updateCredentialLabelInternal(id: string, newLabel: string): boolean {
    return this.updateCredentialInternal(id, { accountLabel: newLabel });
  }
  updateCredentialTokens(ownerId: string, id: string, secret: string, metadataUpdates?: Record<string, unknown>): boolean {
    if (this.#closed) return false;
    this.#ensureMetadataEncryptionVersion();
    const enc = encryptSecret(secret);
    return this.#withMetadataWrite(() => {
      const current = ownerId
        ? (this.#db.prepare("SELECT metadata FROM credentials WHERE owner_id = ? AND id = ?")
            .get(ownerId, id) as { metadata: string | null } | undefined)
        : (this.#db.prepare("SELECT metadata FROM credentials WHERE owner_id IS NULL AND id = ?")
            .get(id) as { metadata: string | null } | undefined);
      if (!current) return false;
      let existing: Record<string, unknown> = {};
      if (current.metadata !== null) {
        existing = decodeCredentialMetadata(current.metadata).metadata;
      }
      const mergedMetadata = { ...existing, ...(metadataUpdates ?? {}) };
      const metadataSerialized = serializeCredentialMetadata(mergedMetadata, this.#shouldEncryptMetadata());
      const query = ownerId
        ? this.#db.prepare(`
            UPDATE credentials SET encrypted_secret = ?, iv = ?, tag = ?, metadata = ?, updated_at = ?
            WHERE owner_id = ? AND id = ?
          `)
        : this.#db.prepare(`
            UPDATE credentials SET encrypted_secret = ?, iv = ?, tag = ?, metadata = ?, updated_at = ?
            WHERE owner_id IS NULL AND id = ?
          `);
      const result = ownerId
        ? query.run(enc.ciphertext, enc.iv, enc.tag, metadataSerialized, Date.now(), ownerId, id)
        : query.run(enc.ciphertext, enc.iv, enc.tag, metadataSerialized, Date.now(), id);
      return result.changes > 0;
    });
  }

  updateCredentialTokensInternal(id: string, secret: string, metadataUpdates?: Record<string, unknown>): boolean {
    const credential = this.getCredentialInternal(id);
    return credential ? this.updateCredentialTokens(credential.ownerId ?? "", id, secret, metadataUpdates) : false;
  }

  // ==================== Snapshot Management ====================

  saveUsageSnapshot(ownerId: string, report: UsageReport): boolean {
    return this.#saveOwnerScopedSnapshot(ownerId, report);
  }

  saveSnapshot(ownerId: string, report: UsageReport): boolean {
    return this.saveUsageSnapshot(ownerId, report);
  }

  #saveOwnerScopedSnapshot(ownerId: string, report: UsageReport): boolean {
    if (this.#closed || !report || !report.credentialId || !ownerId) return false;

    if (report.ownerId && report.ownerId !== ownerId) return false;

    const cleanReport: UsageReport = {
      ownerId,
      provider: report.provider,
      credentialId: report.credentialId,
      accountLabel: report.accountLabel,
      fetchedAt: report.fetchedAt,
      limits: report.limits || [],
      error: report.error,
      health: report.health,
      stale: report.stale,
      lastGoodFetchedAt: report.lastGoodFetchedAt,
      source: report.source,
    };

    const res = this.#db.prepare(`
      INSERT INTO usage_snapshots (owner_id, credential_id, provider, account_label, report_json, fetched_at)
      SELECT c.owner_id, c.id, ?, ?, ?, ?
      FROM credentials c
      WHERE c.id = ? AND c.owner_id = ?
    `).run(
      report.provider,
      report.accountLabel || "Default",
      JSON.stringify(cleanReport),
      report.fetchedAt,
      report.credentialId,
      ownerId,
    );

    return res.changes > 0;
  }

  /**
   * Explicit internal snapshot write for daemon poller with owner inference.
   * Inaccessible to user-scoped callers who must provide their ownerId.
   */
  saveUsageSnapshotInternal(report: UsageReport): boolean {
    if (this.#closed || !report || !report.credentialId) return false;

    const cred = this.#db.prepare(`
      SELECT id, owner_id, provider, account_label
      FROM credentials
      WHERE id = ?
    `).get(report.credentialId) as { id: string; owner_id: string | null; provider: string; account_label: string } | undefined;

    if (!cred) return false;

    if (report.ownerId && report.ownerId !== cred.owner_id) {
      return false;
    }
    const resolvedOwnerId = cred.owner_id ?? null;
    const cleanReport: UsageReport = {
      ownerId: resolvedOwnerId ?? undefined,
      provider: report.provider,
      credentialId: report.credentialId,
      accountLabel: report.accountLabel || cred.account_label,
      fetchedAt: report.fetchedAt,
      limits: report.limits || [],
      error: report.error,
      health: report.health,
      stale: report.stale,
      lastGoodFetchedAt: report.lastGoodFetchedAt,
      source: report.source,
    };

    const res = this.#db.prepare(`
      INSERT INTO usage_snapshots (owner_id, credential_id, provider, account_label, report_json, fetched_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      resolvedOwnerId,
      cred.id,
      report.provider,
      report.accountLabel || cred.account_label || "Default",
      JSON.stringify(cleanReport),
      report.fetchedAt,
    );

    return res.changes > 0;
  }

  getLatestUsage(ownerId: string): UsageReport[] {
    const rows = this.#db.prepare(`
      SELECT s.report_json FROM usage_snapshots s
      INNER JOIN credentials c ON c.id = s.credential_id AND c.owner_id = ?
      INNER JOIN (
        SELECT credential_id, MAX(fetched_at) AS max_time
        FROM usage_snapshots WHERE owner_id = ?
        GROUP BY credential_id
      ) latest ON s.credential_id = latest.credential_id AND s.fetched_at = latest.max_time
      WHERE s.owner_id = ?
      ORDER BY s.id DESC
    `).all(ownerId, ownerId, ownerId) as { report_json: string }[];
    const result: UsageReport[] = [];
    const seenCreds = new Set<string>();
    for (const row of rows) {
      try {
        const report = JSON.parse(row.report_json) as UsageReport;
        delete report.raw;
        if (report.credentialId && !seenCreds.has(report.credentialId)) {
          seenCreds.add(report.credentialId);
          result.push({ ...report, ownerId });
        }
      } catch {}
    }
    return result;
  }
  getLatestUsageInternal(): UsageReport[] {
    const rows = this.#db.prepare(`
      SELECT s.report_json, s.owner_id FROM usage_snapshots s
      INNER JOIN (
        SELECT credential_id, MAX(fetched_at) AS max_time
        FROM usage_snapshots
        GROUP BY credential_id
      ) latest ON s.credential_id = latest.credential_id AND s.fetched_at = latest.max_time
      ORDER BY s.id DESC
    `).all() as { report_json: string; owner_id: string | null }[];

    const result: UsageReport[] = [];
    const seenCreds = new Set<string>();
    for (const row of rows) {
      try {
        const report = JSON.parse(row.report_json) as UsageReport;
        delete report.raw;
        if (report.credentialId && !seenCreds.has(report.credentialId)) {
          seenCreds.add(report.credentialId);
          result.push({ ...report, ownerId: row.owner_id ?? undefined });
        }
      } catch {}
    }
    return result;
  }
  getLatestSnapshots(ownerId: string): UsageReport[] {
    return this.getLatestUsage(ownerId);
  }

  getSnapshotHistory(ownerId: string, provider: string, hours: number = 24): UsageReport[] {
    const cutoff = Date.now() - hours * 60 * 60 * 1000;
    const rows = this.#db.prepare(`
      SELECT s.report_json FROM usage_snapshots s
      INNER JOIN credentials c ON c.id = s.credential_id AND c.owner_id = ?
      WHERE s.owner_id = ? AND s.provider = ? AND s.fetched_at >= ?
      ORDER BY s.fetched_at ASC
    `).all(ownerId, ownerId, provider.toLowerCase(), cutoff) as { report_json: string }[];

    const result: UsageReport[] = [];
    for (const row of rows) {
      try {
        const report = JSON.parse(row.report_json) as UsageReport;
        delete report.raw;
        result.push({ ...report, ownerId });
      } catch {}
    }
    return result;
  }

  getLastSuccessfulUsage(ownerId: string, credentialId: string): UsageReport | null {
    if (this.#closed || !ownerId || !credentialId) return null;
    const rows = this.#db.prepare(`
      SELECT s.report_json, s.owner_id FROM usage_snapshots s
      INNER JOIN credentials c ON c.id = s.credential_id AND c.owner_id = ?
      WHERE s.owner_id = ? AND s.credential_id = ?
      ORDER BY s.fetched_at DESC, s.id DESC
    `).all(ownerId, ownerId, credentialId) as { report_json: string; owner_id: string | null }[];

    for (const row of rows) {
      try {
        const report = JSON.parse(row.report_json) as UsageReport;
        delete report.raw;
        if (report.error) continue;
        if (report.health === "error" || report.health === "stale") continue;
        if (report.source === "error" || report.source === "stale") continue;
        if (report.stale === true) continue;

        return {
          ...report,
          ownerId: row.owner_id ?? ownerId,
          health: report.health ?? "healthy",
          stale: report.stale ?? false,
          source: report.source ?? "live",
          lastGoodFetchedAt: report.lastGoodFetchedAt ?? report.fetchedAt,
        };
      } catch {}
    }
    return null;
  }

  getLastSuccessfulUsageInternal(credentialId: string): UsageReport | null {
    if (this.#closed || !credentialId) return null;
    const rows = this.#db.prepare(`
      SELECT s.report_json, s.owner_id FROM usage_snapshots s
      WHERE s.credential_id = ?
      ORDER BY s.fetched_at DESC, s.id DESC
    `).all(credentialId) as { report_json: string; owner_id: string | null }[];

    for (const row of rows) {
      try {
        const report = JSON.parse(row.report_json) as UsageReport;
        delete report.raw;
        if (report.error) continue;
        if (report.health === "error" || report.health === "stale") continue;
        if (report.source === "error" || report.source === "stale") continue;
        if (report.stale === true) continue;

        return {
          ...report,
          ownerId: row.owner_id ?? report.ownerId,
          health: report.health ?? "healthy",
          stale: report.stale ?? false,
          source: report.source ?? "live",
          lastGoodFetchedAt: report.lastGoodFetchedAt ?? report.fetchedAt,
        };
      } catch {}
    }
    return null;
  }

  // ==================== Health & Lifecycle ====================

  checkIntegrity(): boolean {
    const row = this.#db.prepare("PRAGMA quick_check;").get() as { quick_check: string };
    return row.quick_check === "ok";
  }

  close(): void {
    this.#closed = true;
    this.#db.close();
  }

  #rowToStoredCredential(row: CredentialRow): StoredCredential {
    let secret = "";
    try {
      secret = decryptSecret({ ciphertext: row.encrypted_secret, iv: row.iv, tag: row.tag });
    } catch {}
    const accent = row.accent && CARD_ACCENTS[row.accent] ? (row.accent as CardAccent) : "default";
    let metadata: Record<string, unknown> | undefined;
    if (row.metadata !== null) {
      metadata = decodeCredentialMetadata(row.metadata).metadata;
    }
    return {
      id: row.id,
      ownerId: (row.owner_id ?? undefined) as unknown as string,
      provider: row.provider,
      accountLabel: row.account_label,
      accent,
      credentialType: row.credential_type as StoredCredential["credentialType"],
      secret,
      metadata,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}

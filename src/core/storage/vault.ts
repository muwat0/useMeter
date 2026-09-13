import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret } from "../crypto";
import type { CardAccent, InputCredential, StoredCredential, UsageReport } from "../../types";

const CARD_ACCENTS = new Set<CardAccent>(["default", "amber", "emerald", "cyan", "violet", "slate"]);

export class StorageVault {
  readonly #db: Database;
  #closed = false;

  constructor(dbPath: string = "data/usage.db") {
    const dir = dbPath.includes("/") ? dbPath.slice(0, dbPath.lastIndexOf("/")) : "";
    if (dir) {
      try {
        const fs = require("node:fs");
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      } catch {}
    }

    this.#db = new Database(dbPath, { create: true });
    this.#initPragmas();
    this.#initSchema();
  }

  #initPragmas(): void {
    this.#db.exec("PRAGMA journal_mode = WAL;");
    this.#db.exec("PRAGMA synchronous = NORMAL;");
    this.#db.exec("PRAGMA foreign_keys = ON;");
    this.#db.exec("PRAGMA busy_timeout = 5000;");
  }

  #initSchema(): void {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
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
      CREATE TABLE IF NOT EXISTS usage_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        account_label TEXT NOT NULL,
        report_json TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_snapshots_cred_time
        ON usage_snapshots(credential_id, fetched_at DESC);
    `);
    try {
      this.#db.exec("ALTER TABLE credentials ADD COLUMN accent TEXT NOT NULL DEFAULT 'default'");
    } catch {}
  }

  saveCredential(input: InputCredential): StoredCredential {
    const provider = input.provider.toLowerCase();
    const accent = input.accent && CARD_ACCENTS.has(input.accent) ? input.accent : "default";
    const existing = this.#db.prepare(`
      SELECT id, created_at FROM credentials WHERE provider = ? AND account_label = ?
    `).get(provider, input.accountLabel) as { id: string; created_at: number } | undefined;
    const now = Date.now();
    const enc = encryptSecret(input.secret);
    const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null;

    if (existing) {
      this.#db.prepare(`
        UPDATE credentials SET
          accent = ?, credential_type = ?, encrypted_secret = ?, iv = ?, tag = ?, metadata = ?, updated_at = ?
        WHERE id = ?
      `).run(accent, input.credentialType, enc.ciphertext, enc.iv, enc.tag, metadataJson, now, existing.id);
      return {
        id: existing.id,
        provider,
        accountLabel: input.accountLabel,
        accent,
        credentialType: input.credentialType,
        secret: input.secret,
        metadata: input.metadata,
        createdAt: existing.created_at,
        updatedAt: now,
      };
    }

    const id = randomUUID();
    this.#db.prepare(`
      INSERT INTO credentials (
        id, provider, account_label, accent, credential_type,
        encrypted_secret, iv, tag, metadata, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, provider, input.accountLabel, accent, input.credentialType, enc.ciphertext, enc.iv, enc.tag, metadataJson, now, now);

    return {
      id,
      provider,
      accountLabel: input.accountLabel,
      accent,
      credentialType: input.credentialType,
      secret: input.secret,
      metadata: input.metadata,
      createdAt: now,
      updatedAt: now,
    };
  }

  listCredentials(provider?: string): StoredCredential[] {
    interface CredentialRow {
      id: string;
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

    const rows = provider
      ? this.#db.prepare("SELECT * FROM credentials WHERE provider = ? ORDER BY created_at ASC").all(provider.toLowerCase()) as CredentialRow[]
      : this.#db.prepare("SELECT * FROM credentials ORDER BY provider ASC, created_at ASC").all() as CredentialRow[];

    return rows.map(row => {
      let secret = "";
      try {
        secret = decryptSecret({ ciphertext: row.encrypted_secret, iv: row.iv, tag: row.tag });
      } catch {}

      const accent = CARD_ACCENTS.has(row.accent as CardAccent) ? row.accent as CardAccent : "default";
      return {
        id: row.id,
        provider: row.provider,
        accountLabel: row.account_label,
        accent,
        credentialType: row.credential_type as StoredCredential["credentialType"],
        secret,
        metadata: row.metadata ? JSON.parse(row.metadata) as Record<string, unknown> : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      };
    });
  }

  deleteCredential(id: string): boolean {
    if (this.#closed) return false;
    const result = this.#db.prepare("DELETE FROM credentials WHERE id = ?").run(id);
    return result.changes > 0;
  }

  updateCredential(id: string, changes: { accountLabel?: string; accent?: CardAccent }): boolean {
    if (this.#closed) return false;
    const label = changes.accountLabel?.trim();
    if (changes.accountLabel !== undefined && !label) return false;
    if (changes.accent !== undefined && !CARD_ACCENTS.has(changes.accent)) return false;

    const current = this.#db.prepare("SELECT account_label, accent FROM credentials WHERE id = ?").get(id) as { account_label: string; accent: string } | undefined;
    if (!current) return false;
    const nextLabel = label ?? current.account_label;
    const nextAccent = changes.accent ?? (CARD_ACCENTS.has(current.accent as CardAccent) ? current.accent : "default");
    const result = this.#db.prepare("UPDATE credentials SET account_label = ?, accent = ?, updated_at = ? WHERE id = ?").run(nextLabel, nextAccent, Date.now(), id);
    if (result.changes > 0) {
      this.#db.prepare("UPDATE usage_snapshots SET account_label = ? WHERE credential_id = ?").run(nextLabel, id);
      return true;
    }
    return false;
  }

  updateCredentialLabel(id: string, newLabel: string): boolean {
    return this.updateCredential(id, { accountLabel: newLabel });
  }

  saveUsageSnapshot(report: UsageReport): void {
    if (this.#closed || !report.credentialId) return;
    const cleanReport: UsageReport = {
      provider: report.provider,
      credentialId: report.credentialId,
      accountLabel: report.accountLabel,
      fetchedAt: report.fetchedAt,
      limits: report.limits || [],
    };
    this.#db.prepare(`
      INSERT INTO usage_snapshots (credential_id, provider, account_label, report_json, fetched_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(report.credentialId, report.provider, report.accountLabel || "Default", JSON.stringify(cleanReport), report.fetchedAt);
  }

  getLatestUsage(): UsageReport[] {
    const rows = this.#db.prepare(`
      SELECT s.report_json FROM usage_snapshots s
      INNER JOIN (
        SELECT credential_id, MAX(fetched_at) AS max_time FROM usage_snapshots GROUP BY credential_id
      ) latest ON s.credential_id = latest.credential_id AND s.fetched_at = latest.max_time
    `).all() as { report_json: string }[];
    const result: UsageReport[] = [];
    for (const row of rows) {
      try {
        const report = JSON.parse(row.report_json) as UsageReport;
        delete report.raw;
        result.push(report);
      } catch {}
    }
    return result;
  }

  checkIntegrity(): boolean {
    const row = this.#db.prepare("PRAGMA quick_check;").get() as { quick_check: string };
    return row.quick_check === "ok";
  }

  close(): void {
    this.#closed = true;
    this.#db.close();
  }
}

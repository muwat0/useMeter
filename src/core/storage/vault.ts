import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret } from "../crypto";
import type { InputCredential, StoredCredential, UsageLimit, UsageReport } from "../../types";

export class StorageVault {
  readonly #db: Database;
  #closed = false;
  constructor(dbPath: string = "data/usage.db") {
    // Ensure directory exists if needed
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
  }

  saveCredential(input: InputCredential): StoredCredential {
    const provider = input.provider.toLowerCase();
    const existing = this.#db.prepare(`
      SELECT id, created_at FROM credentials WHERE provider = ? AND account_label = ?
    `).get(provider, input.accountLabel) as { id: string; created_at: number } | undefined;

    const now = Date.now();
    const enc = encryptSecret(input.secret);
    const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null;

    if (existing) {
      this.#db.prepare(`
        UPDATE credentials SET
          credential_type = ?,
          encrypted_secret = ?,
          iv = ?,
          tag = ?,
          metadata = ?,
          updated_at = ?
        WHERE id = ?
      `).run(
        input.credentialType,
        enc.ciphertext,
        enc.iv,
        enc.tag,
        metadataJson,
        now,
        existing.id,
      );

      return {
        id: existing.id,
        provider,
        accountLabel: input.accountLabel,
        credentialType: input.credentialType,
        secret: input.secret,
        metadata: input.metadata,
        createdAt: existing.created_at,
        updatedAt: now,
      };
    }

    const id = randomUUID();
    const query = this.#db.prepare(`
      INSERT INTO credentials (
        id, provider, account_label, credential_type,
        encrypted_secret, iv, tag, metadata,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    query.run(
      id,
      provider,
      input.accountLabel,
      input.credentialType,
      enc.ciphertext,
      enc.iv,
      enc.tag,
      metadataJson,
      now,
      now,
    );
    return {
      id,
      provider: input.provider.toLowerCase(),
      accountLabel: input.accountLabel,
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
      credential_type: string;
      encrypted_secret: string;
      iv: string;
      tag: string;
      metadata: string | null;
      created_at: number;
      updated_at: number;
    }

    let rows: CredentialRow[];
    if (provider) {
      const stmt = this.#db.prepare(`SELECT * FROM credentials WHERE provider = ? ORDER BY created_at ASC`);
      rows = stmt.all(provider.toLowerCase()) as CredentialRow[];
    } else {
      const stmt = this.#db.prepare(`SELECT * FROM credentials ORDER BY provider ASC, created_at ASC`);
      rows = stmt.all() as CredentialRow[];
    }

    return rows.map(row => {
      let secret = "";
      try {
        secret = decryptSecret({
          ciphertext: row.encrypted_secret,
          iv: row.iv,
          tag: row.tag,
        });
      } catch (err) {
        secret = "[DECRYPTION_ERROR]";
      }

      return {
        id: row.id,
        provider: row.provider,
        accountLabel: row.account_label,
        credentialType: row.credential_type as StoredCredential["credentialType"],
        secret,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      };
    });
  }
  deleteCredential(id: string): boolean {
    if (this.#closed) return false;
    const stmt = this.#db.prepare(`DELETE FROM credentials WHERE id = ?`);
    const result = stmt.run(id);
    return result.changes > 0;
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

    const stmt = this.#db.prepare(`
      INSERT INTO usage_snapshots (
        credential_id, provider, account_label, report_json, fetched_at
      ) VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      report.credentialId,
      report.provider,
      report.accountLabel || "Default",
      JSON.stringify(cleanReport),
      report.fetchedAt,
    );
  }

  getLatestUsage(): UsageReport[] {
    const stmt = this.#db.prepare(`
      SELECT s.report_json
      FROM usage_snapshots s
      INNER JOIN (
        SELECT credential_id, MAX(fetched_at) as max_time
        FROM usage_snapshots
        GROUP BY credential_id
      ) latest ON s.credential_id = latest.credential_id AND s.fetched_at = latest.max_time
    `);

    const rows = stmt.all() as { report_json: string }[];
    const result: UsageReport[] = [];
    for (const r of rows) {
      try {
        const parsed = JSON.parse(r.report_json) as UsageReport;
        delete parsed.raw;
        result.push(parsed);
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

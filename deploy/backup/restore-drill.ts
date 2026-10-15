import { Database } from "bun:sqlite";

export interface BackupDrillResult {
  schemaVersion: 2;
  quickCheck: "ok";
  integrityCheck: "ok";
  credentials: number;
  snapshots: number;
  encryptedMetadataEnvelopes: number;
}

class BackupDrillError extends Error {}

function pragmaIsOk(rows: unknown[]): boolean {
  return rows.length > 0 && rows.every(row => {
    if (typeof row !== "object" || row === null) return false;
    const values = Object.values(row);
    return values.length === 1 && values[0] === "ok";
  });
}

function isValidMetadataEnvelope(value: unknown): boolean {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    !("$vault" in value) ||
    !("ciphertext" in value) ||
    !("iv" in value) ||
    !("tag" in value)
  ) return false;
  const keys = Object.keys(value);
  return value["$vault"] === 1 &&
    keys.length === 4 &&
    typeof value["ciphertext"] === "string" &&
    /^(?:[0-9a-f]{2})*$/i.test(value["ciphertext"]) &&
    typeof value["iv"] === "string" &&
    /^[0-9a-f]{24}$/i.test(value["iv"]) &&
    typeof value["tag"] === "string" &&
    /^[0-9a-f]{32}$/i.test(value["tag"]);
}

/** Opens only a standalone candidate file in read-only/query-only mode. */
export function validateBackup(backupPath: string): BackupDrillResult {
  if (!backupPath.trim()) throw new BackupDrillError("Backup path is required.");

  let database: Database;
  try {
    database = new Database(backupPath, { readonly: true });
  } catch {
    throw new BackupDrillError("Backup could not be opened read-only.");
  }

  try {
    database.exec("PRAGMA query_only = ON;");
    const versionRow: unknown = database.prepare("PRAGMA user_version;").get();
    if (
      typeof versionRow !== "object" ||
      versionRow === null ||
      !("user_version" in versionRow) ||
      versionRow.user_version !== 2
    ) throw new BackupDrillError("Backup schema version must be 2.");

    const quickRows: unknown[] = database.prepare("PRAGMA quick_check;").all();
    if (!pragmaIsOk(quickRows)) {
      throw new BackupDrillError("Backup quick_check failed.");
    }
    const integrityRows: unknown[] = database.prepare("PRAGMA integrity_check;").all();
    if (!pragmaIsOk(integrityRows)) {
      throw new BackupDrillError("Backup integrity_check failed.");
    }

    const credentialRows: unknown[] = database.prepare("SELECT metadata FROM credentials;").all();
    let encryptedMetadataEnvelopes = 0;
    for (const row of credentialRows) {
      if (typeof row !== "object" || row === null || !("metadata" in row)) {
        throw new BackupDrillError("Backup credential metadata is unreadable.");
      }
      if (row.metadata === null) continue;
      if (typeof row.metadata !== "string") {
        throw new BackupDrillError("Backup credential metadata is unreadable.");
      }
      let metadata: unknown;
      try {
        metadata = JSON.parse(row.metadata);
      } catch {
        throw new BackupDrillError("Backup contains malformed credential metadata.");
      }
      if (!isValidMetadataEnvelope(metadata)) {
        throw new BackupDrillError("Backup contains an invalid encrypted metadata envelope.");
      }
      encryptedMetadataEnvelopes++;
    }

    const snapshotRow: unknown = database.prepare("SELECT COUNT(*) AS count FROM usage_snapshots;").get();
    if (
      typeof snapshotRow !== "object" ||
      snapshotRow === null ||
      !("count" in snapshotRow) ||
      typeof snapshotRow.count !== "number"
    ) throw new BackupDrillError("Backup snapshot count is unreadable.");

    return {
      schemaVersion: 2,
      quickCheck: "ok",
      integrityCheck: "ok",
      credentials: credentialRows.length,
      snapshots: snapshotRow.count,
      encryptedMetadataEnvelopes,
    };
  } catch (error) {
    if (error instanceof BackupDrillError) throw error;
    throw new BackupDrillError("Backup is unreadable or missing required schema.");
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  const backupPath = process.argv[2];
  if (!backupPath) {
    console.error("Restore drill requires a candidate backup file.");
    process.exitCode = 2;
  } else {
    try {
      console.log(JSON.stringify(validateBackup(backupPath)));
    } catch (error) {
      const message = error instanceof BackupDrillError ? error.message : "Backup could not be verified.";
      console.error(`Restore drill failed: ${message}`);
      process.exitCode = 1;
    }
  }
}

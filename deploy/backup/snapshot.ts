import { Database } from "bun:sqlite";
import { chmodSync, closeSync, existsSync, lstatSync, openSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";

export interface BackupSnapshotResult {
  schemaVersion: 2;
  quickCheck: "ok";
  integrityCheck: "ok";
  credentials: number;
  snapshots: number;
}

const TEMPORARY_VOLUME_PATH = /^\/app\/data\/\.usemeter-backup-[A-Za-z0-9-]+\.sqlite$/;

function pragmaRowsAreOk(rows: unknown[]): boolean {
  return rows.length > 0 && rows.every(row => {
    if (typeof row !== "object" || row === null) return false;
    const values = Object.values(row);
    return values.length === 1 && values[0] === "ok";
  });
}

function assertSnapshotChecks(database: Database): BackupSnapshotResult {
  const versionRow: unknown = database.prepare("PRAGMA user_version;").get();
  if (
    typeof versionRow !== "object" ||
    versionRow === null ||
    !("user_version" in versionRow) ||
    versionRow.user_version !== 2
  ) throw new Error("Database schema version must be 2.");

  const quickRows: unknown[] = database.prepare("PRAGMA quick_check;").all();
  if (!pragmaRowsAreOk(quickRows)) {
    throw new Error("Database quick_check failed.");
  }
  const integrityRows: unknown[] = database.prepare("PRAGMA integrity_check;").all();
  if (!pragmaRowsAreOk(integrityRows)) {
    throw new Error("Database integrity_check failed.");
  }
  const credentialRow: unknown = database.prepare("SELECT COUNT(*) AS count FROM credentials;").get();
  const snapshotRow: unknown = database.prepare("SELECT COUNT(*) AS count FROM usage_snapshots;").get();
  if (
    typeof credentialRow !== "object" || credentialRow === null || !("count" in credentialRow) ||
    typeof credentialRow.count !== "number" ||
    typeof snapshotRow !== "object" || snapshotRow === null || !("count" in snapshotRow) ||
    typeof snapshotRow.count !== "number"
  ) throw new Error("Database row counts could not be read.");
  return {
    schemaVersion: 2,
    quickCheck: "ok",
    integrityCheck: "ok",
    credentials: credentialRow.count,
    snapshots: snapshotRow.count,
  };
}

/** Creates a standalone, WAL-consistent snapshot without instantiating StorageVault. */
export function createSnapshot(sourcePath: string, destinationPath: string): BackupSnapshotResult {
  if (resolve(sourcePath) === resolve(destinationPath)) {
    throw new Error("Snapshot destination must differ from the source database.");
  }
  if (existsSync(destinationPath)) {
    throw new Error("Snapshot destination already exists.");
  }

  const previousUmask = process.umask(0o077);
  let ownsDestination = false;
  let complete = false;
  try {
    const descriptor = openSync(destinationPath, "wx", 0o600);
    ownsDestination = true;
    closeSync(descriptor);

    const source = new Database(sourcePath, { readwrite: true, create: false });
    try {
      const quotedDestination = destinationPath.replaceAll("'", "''");
      source.exec(`VACUUM INTO '${quotedDestination}';`);
    } finally {
      source.close();
    }
    chmodSync(destinationPath, 0o600);

    const snapshot = new Database(destinationPath, { readonly: true });
    let result: BackupSnapshotResult;
    try {
      result = assertSnapshotChecks(snapshot);
    } finally {
      snapshot.close();
    }
    complete = true;
    return result;
  } finally {
    try {
      if (ownsDestination && !complete) {
        try {
          unlinkSync(destinationPath);
        } catch (error) {
          if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
        }
      }
    } finally {
      process.umask(previousUmask);
    }
  }
}

function removeTemporaryVolumeSnapshot(path: string): void {
  if (!TEMPORARY_VOLUME_PATH.test(path)) {
    throw new Error("Temporary backup path is invalid.");
  }
  try {
    const file = lstatSync(path);
    if (!file.isFile() || file.isSymbolicLink()) {
      throw new Error("Temporary backup path is not a regular file.");
    }
    unlinkSync(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
}

if (import.meta.main) {
  try {
    const action = process.argv[2];
    if (action === "create") {
      const destinationPath = process.env["USEMETER_BACKUP_TEMP_PATH"] ?? "";
      if (!TEMPORARY_VOLUME_PATH.test(destinationPath)) {
        throw new Error("Temporary backup path is invalid.");
      }
      const sourcePath = process.env["DATABASE_PATH"] || "/app/data/usage.db";
      console.log(JSON.stringify(createSnapshot(sourcePath, destinationPath)));
    } else if (action === "remove") {
      const destinationPath = process.env["USEMETER_BACKUP_TEMP_PATH"] ?? "";
      removeTemporaryVolumeSnapshot(destinationPath);
    } else {
      throw new Error("Snapshot action must be create or remove.");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Snapshot operation failed.";
    console.error(`Backup snapshot failed: ${message}`);
    process.exitCode = 1;
  }
}

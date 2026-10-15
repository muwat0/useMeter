import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "bun:test";
import { createSnapshot } from "../deploy/backup/snapshot";
import { validateBackup } from "../deploy/backup/restore-drill";

const VALID_ENVELOPE = JSON.stringify({
  $vault: 1,
  ciphertext: "0011aabb",
  iv: "0123456789abcdef01234567",
  tag: "0123456789abcdef0123456789abcdef",
});

const temporaryDirectories: string[] = [];

function createDatabase(path: string, version = 2, metadata: string | null = VALID_ENVELOPE): void {
  const database = new Database(path);
  database.exec(`
    CREATE TABLE credentials (id TEXT PRIMARY KEY, metadata TEXT);
    CREATE TABLE usage_snapshots (id INTEGER PRIMARY KEY);
    PRAGMA user_version = ${version};
  `);
  database.prepare("INSERT INTO credentials (id, metadata) VALUES (?, ?);").run("credential-1", metadata);
  database.prepare("INSERT INTO credentials (id, metadata) VALUES (?, NULL);").run("credential-2");
  database.prepare("INSERT INTO usage_snapshots DEFAULT VALUES;").run();
  database.prepare("INSERT INTO usage_snapshots DEFAULT VALUES;").run();
  database.close();
}

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), "usemeter-backup-drill-"));
  temporaryDirectories.push(path);
  return path;
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("isolated backup restore drill", () => {
  it("creates and validates a schema-v2 standalone snapshot without changing its source", () => {
    const directory = temporaryDirectory();
    const source = join(directory, "source.sqlite");
    const backup = join(directory, "candidate.sqlite");
    createDatabase(source);
    const sourceBefore = sha256(source);

    const created = createSnapshot(source, backup);
    expect(statSync(backup).mode & 0o777).toBe(0o600);
    const drilled = validateBackup(backup);

    expect(created).toEqual({
      schemaVersion: 2,
      quickCheck: "ok",
      integrityCheck: "ok",
      credentials: 2,
      snapshots: 2,
    });
    expect(drilled).toEqual({
      schemaVersion: 2,
      quickCheck: "ok",
      integrityCheck: "ok",
      credentials: 2,
      snapshots: 2,
      encryptedMetadataEnvelopes: 1,
    });
    expect(sha256(source)).toBe(sourceBefore);
  });

  it("includes committed WAL data while the source connection remains open", () => {
    const directory = temporaryDirectory();
    const source = join(directory, "wal-source.sqlite");
    const backup = join(directory, "wal-candidate.sqlite");
    createDatabase(source);
    const liveConnection = new Database(source, { readwrite: true, create: false });

    try {
      liveConnection.exec("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;");
      liveConnection.prepare("INSERT INTO usage_snapshots DEFAULT VALUES;").run();
      expect(existsSync(`${source}-wal`)).toBe(true);

      expect(createSnapshot(source, backup).snapshots).toBe(3);
      expect(validateBackup(backup).snapshots).toBe(3);
    } finally {
      liveConnection.close();
    }
  });

  it("rejects a candidate unless its schema version is exactly 2", () => {
    const path = join(temporaryDirectory(), "schema-v1.sqlite");
    createDatabase(path, 1);

    expect(() => validateBackup(path)).toThrow("Backup schema version must be 2.");
  });

  it("rejects malformed or non-v1 encrypted metadata envelopes", () => {
    const directory = temporaryDirectory();
    const malformed = join(directory, "malformed-envelope.sqlite");
    const unsupported = join(directory, "unsupported-envelope.sqlite");
    createDatabase(malformed, 2, JSON.stringify({ $vault: 1, ciphertext: "not-hex", iv: "short", tag: "short" }));
    createDatabase(unsupported, 2, JSON.stringify({
      $vault: 2,
      ciphertext: "0011",
      iv: "0123456789abcdef01234567",
      tag: "0123456789abcdef0123456789abcdef",
    }));

    expect(() => validateBackup(malformed)).toThrow("invalid encrypted metadata envelope");
    expect(() => validateBackup(unsupported)).toThrow("invalid encrypted metadata envelope");
  });

  it("opens the candidate read-only and leaves its bytes unchanged", () => {
    const path = join(temporaryDirectory(), "readonly.sqlite");
    createDatabase(path);
    const before = sha256(path);

    expect(validateBackup(path).credentials).toBe(2);
    expect(sha256(path)).toBe(before);
  });

  it("rejects databases missing the required credential and snapshot tables", () => {
    const path = join(temporaryDirectory(), "missing-schema.sqlite");
    const database = new Database(path);
    database.exec("PRAGMA user_version = 2;");
    database.close();

    expect(() => validateBackup(path)).toThrow("Backup is unreadable or missing required schema.");
  });
});

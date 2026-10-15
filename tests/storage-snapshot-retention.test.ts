import { Database } from "bun:sqlite";
import { describe, expect, it, vi } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StorageVault } from "../src/core/storage/vault";
import { UsageSnapshotRetention } from "../src/core/storage/retention";
import type { UsageReport } from "../src/types";

const DAY = 24 * 60 * 60 * 1_000;
const PROVIDER = "retention-test";

interface TestFixture {
  vault: StorageVault;
  db: Database;
  createUser(label: string): { id: string };
  createCredential(ownerId: string, label: string): string;
  insert(
    ownerId: string,
    credentialId: string,
    fetchedAt: number,
    overrides?: Record<string, unknown>,
  ): number;
  insertManyErrors(
    ownerId: string,
    credentialId: string,
    count: number,
    firstFetchedAt: number,
  ): void;
  snapshotIds(): number[];
  setReportJson(id: number, reportJson: string): void;
  closeVault(): void;
  close(): void;
}

function createFixture(): TestFixture {
  const directory = mkdtempSync(join(tmpdir(), "usemeter-retention-"));
  const dbPath = join(directory, "usage.sqlite");
  const vault = new StorageVault(dbPath);
  const db = new Database(dbPath);
  const labels = new Map<string, string>();
  let userNumber = 0;
  let vaultClosed = false;

  return {
    vault,
    db,
    createUser(label) {
      userNumber += 1;
      return vault.createUser(`${label}-${userNumber}@example.com`, "test-password-hash");
    },
    createCredential(ownerId, label) {
      const credential = vault.saveCredential(ownerId, {
        provider: PROVIDER,
        accountLabel: label,
        credentialType: "api_key",
        secret: `secret-${label}`,
        metadata: {
          refreshToken: `fixture-refresh-${label}`,
          accountId: `fixture-account-${label}`,
        },
      });
      labels.set(credential.id, label);
      return credential.id;
    },
    insert(ownerId, credentialId, fetchedAt, overrides = {}) {
      const report = {
        ownerId,
        provider: PROVIDER,
        credentialId,
        accountLabel: labels.get(credentialId) ?? "Missing label",
        fetchedAt,
        limits: [{
          id: "requests",
          label: "Requests",
          amount: { remaining: 25, unit: "requests" },
          status: "ok",
        }],
        ...overrides,
      } as UsageReport;
      if (!vault.saveUsageSnapshot(ownerId, report)) {
        throw new Error("Could not save a retention test snapshot.");
      }
      const row = db.prepare(`
        SELECT id FROM usage_snapshots
        WHERE credential_id = ? AND fetched_at = ?
        ORDER BY id DESC LIMIT 1
      `).get(credentialId, fetchedAt) as { id: number } | undefined;
      if (!row) throw new Error("Saved retention snapshot was not found.");
      return row.id;
    },
    insertManyErrors(ownerId, credentialId, count, firstFetchedAt) {
      const label = labels.get(credentialId) ?? "Missing label";
      const insert = db.prepare(`
        INSERT INTO usage_snapshots (
          owner_id, credential_id, provider, account_label, report_json, fetched_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);
      const write = db.transaction(() => {
        for (let index = 0; index < count; index += 1) {
          const fetchedAt = firstFetchedAt + index;
          const report: UsageReport = {
            ownerId,
            provider: PROVIDER,
            credentialId,
            accountLabel: label,
            fetchedAt,
            limits: [],
            error: "provider unavailable",
            health: "error",
            stale: true,
            source: "error",
          };
          insert.run(ownerId, credentialId, PROVIDER, label, JSON.stringify(report), fetchedAt);
        }
      });
      write();
    },
    snapshotIds() {
      return (db.prepare("SELECT id FROM usage_snapshots ORDER BY id").all() as { id: number }[])
        .map(row => row.id);
    },
    setReportJson(id, reportJson) {
      db.prepare("UPDATE usage_snapshots SET report_json = ? WHERE id = ?").run(reportJson, id);
    },
    closeVault() {
      if (vaultClosed) return;
      vaultClosed = true;
      vault.close();
    },
    close() {
      db.close();
      if (!vaultClosed) {
        vaultClosed = true;
        vault.close();
      }
      rmSync(directory, { recursive: true, force: true });
    },
  };
}


describe("usage snapshot retention", () => {
  it("keeps the cutoff boundary, two anchors per credential, recent history, and all accounts", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const ownerA = fixture.createUser("retention-a");
      const ownerB = fixture.createUser("retention-b");
      const credentialA = fixture.createCredential(ownerA.id, "Primary A");
      const credentialWindow = fixture.createCredential(ownerA.id, "Window A");
      const credentialQuota = fixture.createCredential(ownerA.id, "Quota A");
      const credentialErrors = fixture.createCredential(ownerA.id, "Errors A");
      const credentialB = fixture.createCredential(ownerB.id, "Primary B");
      const credentialHistory = fixture.createCredential(ownerA.id, "History A");
      const credentialRecent = fixture.createCredential(ownerA.id, "Recent history A");

      const aOldestError = fixture.insert(ownerA.id, credentialA, cutoff - 4 * DAY, {
        error: "first old failure",
        health: "error",
        source: "error",
        stale: true,
        limits: [],
      });
      const aOldLastGood = fixture.insert(ownerA.id, credentialA, cutoff - 3 * DAY, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      const aIntermediateError = fixture.insert(ownerA.id, credentialA, cutoff - 2 * DAY, {
        error: "intermediate failure",
        health: "error",
        source: "error",
        stale: true,
        limits: [],
      });
      const aLatestError = fixture.insert(ownerA.id, credentialA, cutoff - DAY, {
        error: "latest failure",
        health: "error",
        source: "error",
        stale: true,
        limits: [],
      });

      const windowExpired = fixture.insert(ownerA.id, credentialWindow, cutoff - 1, {
        error: "expired",
        health: "error",
        source: "error",
        limits: [],
      });
      const windowBoundary = fixture.insert(ownerA.id, credentialWindow, cutoff, {
        error: "at boundary",
        health: "error",
        source: "error",
        limits: [],
      });
      const windowRecent = fixture.insert(ownerA.id, credentialWindow, cutoff + 1, {
        error: "recent failure",
        health: "error",
        source: "error",
        limits: [],
      });

      const exhaustedQuota = fixture.insert(ownerA.id, credentialQuota, cutoff - 2 * DAY, {
        health: "healthy",
        source: "live",
        stale: false,
        limits: [{
          id: "quota",
          label: "Quota",
          amount: { remaining: 0, limit: 100, unit: "requests" },
          status: "exhausted",
        }],
      });
      const staleQuota = fixture.insert(ownerA.id, credentialQuota, cutoff - DAY, {
        health: "stale",
        source: "stale",
        stale: true,
        limits: [],
      });

      const errorOldest = fixture.insert(ownerA.id, credentialErrors, cutoff - 3 * DAY, {
        error: "first-ever error",
        health: "error",
        source: "error",
        limits: [],
      });
      const errorMiddle = fixture.insert(ownerA.id, credentialErrors, cutoff - 2 * DAY, {
        error: "second error",
        health: "error",
        source: "error",
        limits: [],
      });
      const errorLatest = fixture.insert(ownerA.id, credentialErrors, cutoff - DAY, {
        error: "latest first-ever error",
        health: "error",
        source: "error",
        limits: [],
      });

      const bOldLastGood = fixture.insert(ownerB.id, credentialB, cutoff - 3 * DAY, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      const bDisposableError = fixture.insert(ownerB.id, credentialB, cutoff - 2 * DAY, {
        error: "owner B disposable failure",
        health: "error",
        source: "error",
        limits: [],
      });
      const bLatestError = fixture.insert(ownerB.id, credentialB, cutoff - DAY, {
        error: "owner B latest failure",
        health: "error",
        source: "error",
        limits: [],
      });

      const recentFetchedAt = now - 60 * 60 * 1_000;
      const recentHistory = fixture.insert(ownerA.id, credentialHistory, recentFetchedAt, {
        limits: [{
          id: "requests",
          label: "Requests",
          amount: { used: 8, limit: 50, remaining: 42, unit: "requests" },
          status: "ok",
        }],
      });
      const recentFirst = fixture.insert(ownerA.id, credentialRecent, cutoff + 2, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      const recentSecond = fixture.insert(ownerA.id, credentialRecent, cutoff + 3, {
        error: "recent intermediate error",
        health: "error",
        source: "error",
        limits: [],
      });
      const recentThird = fixture.insert(ownerA.id, credentialRecent, cutoff + 4, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      const recentFourth = fixture.insert(ownerA.id, credentialRecent, cutoff + 5, {
        error: "recent latest error",
        health: "error",
        source: "error",
        limits: [],
      });
      const userCountBefore = fixture.vault.getUserCount();
      const credentialsBefore = [
        ...fixture.vault.listCredentials(ownerA.id),
        ...fixture.vault.listCredentials(ownerB.id),
      ].map(credential => ({
        id: credential.id,
        secret: credential.secret,
        metadata: credential.metadata,
      }));
      const watermark = Math.max(...fixture.snapshotIds());

      const receipt = await fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });

      expect(receipt.cutoff).toBe(cutoff);
      expect(receipt.watermark).toBe(watermark);
      expect(receipt.protectedCount).toBe(11);
      expect(receipt.deletedCount).toBe(6);
      expect(receipt.batches).toBe(1);
      expect(fixture.snapshotIds().sort((a, b) => a - b)).toEqual([
        aOldLastGood,
        aLatestError,
        windowBoundary,
        windowRecent,
        exhaustedQuota,
        staleQuota,
        errorLatest,
        bOldLastGood,
        bLatestError,
        recentHistory,
        recentFirst,
        recentSecond,
        recentThird,
        recentFourth,
      ].sort((a, b) => a - b));
      expect(fixture.snapshotIds()).not.toContain(aOldestError);
      expect(fixture.snapshotIds()).not.toContain(aIntermediateError);
      expect(fixture.snapshotIds()).not.toContain(windowExpired);
      expect(fixture.snapshotIds()).not.toContain(errorOldest);
      expect(fixture.snapshotIds()).not.toContain(errorMiddle);
      expect(fixture.snapshotIds()).not.toContain(bDisposableError);

      const lastGood = fixture.vault.getLastSuccessfulUsage(ownerA.id, credentialQuota);
      expect(lastGood?.fetchedAt).toBe(cutoff - 2 * DAY);
      expect(lastGood?.limits[0]?.status).toBe("exhausted");
      expect(fixture.vault.getLastSuccessfulUsage(ownerA.id, credentialB)).toBeNull();
      expect(fixture.vault.getLastSuccessfulUsage(ownerB.id, credentialA)).toBeNull();
      const history = fixture.vault.getSnapshotHistory(ownerA.id, PROVIDER, 24);
      expect(history).toHaveLength(1);
      expect(history[0]?.ownerId).toBe(ownerA.id);
      expect(history[0]?.fetchedAt).toBe(recentFetchedAt);
      expect(history[0]?.limits[0]?.amount.remaining).toBe(42);

      expect(fixture.vault.getUserCount()).toBe(userCountBefore);
      expect([
        ...fixture.vault.listCredentials(ownerA.id),
        ...fixture.vault.listCredentials(ownerB.id),
      ].map(credential => ({
        id: credential.id,
        secret: credential.secret,
        metadata: credential.metadata,
      }))).toEqual(credentialsBefore);
    } finally {
      fixture.close();
    }
  });

  it("uses fetched-time then descending-id for both anchors, not later insertion order alone", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = fixture.createUser("retention-ties");
      const credential = fixture.createCredential(owner.id, "Tied observations");
      const tiedAt = cutoff - DAY;
      const olderGood = fixture.insert(owner.id, credential, tiedAt, {
        health: "healthy",
        source: "live",
        stale: false,
        limits: [{ id: "quota", label: "Quota", amount: { remaining: 1, unit: "requests" }, status: "ok" }],
      });
      const tiedLastGood = fixture.insert(owner.id, credential, tiedAt, {
        health: "healthy",
        source: "live",
        stale: false,
        limits: [{ id: "quota", label: "Quota", amount: { remaining: 2, unit: "requests" }, status: "ok" }],
      });
      const tiedLatest = fixture.insert(owner.id, credential, tiedAt, {
        error: "same-time failure",
        health: "error",
        source: "error",
        stale: true,
        limits: [],
      });
      const lateOlderObservation = fixture.insert(owner.id, credential, tiedAt - 1, {
        health: "healthy",
        source: "live",
        stale: false,
        limits: [{ id: "quota", label: "Quota", amount: { remaining: 9, unit: "requests" }, status: "ok" }],
      });

      expect(fixture.vault.getLatestUsage(owner.id)[0]?.health).toBe("error");
      expect(fixture.vault.getLatestUsage(owner.id)[0]?.credentialId).toBe(credential);
      expect(fixture.vault.getLastSuccessfulUsage(owner.id, credential)?.limits[0]?.amount.remaining).toBe(2);

      const receipt = await fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
      expect(receipt.protectedCount).toBe(2);
      expect(receipt.deletedCount).toBe(2);
      expect(fixture.snapshotIds().sort((a, b) => a - b)).toEqual([tiedLastGood, tiedLatest]);
      expect(fixture.snapshotIds()).not.toContain(olderGood);
      expect(fixture.snapshotIds()).not.toContain(lateOlderObservation);
      expect(fixture.vault.getLastSuccessfulUsage(owner.id, credential)?.limits[0]?.amount.remaining).toBe(2);
    } finally {
      fixture.close();
    }
  });

  it("matches last-good truthiness for legacy report fields and uses the same predicate for pruning", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = fixture.createUser("retention-classifier");
      const cases: Array<{
        label: string;
        fields: Record<string, unknown>;
        successful: boolean;
      }> = [
        { label: "missing-fields", fields: {}, successful: true },
        { label: "error-null", fields: { error: null }, successful: true },
        { label: "error-false", fields: { error: false }, successful: true },
        { label: "error-zero", fields: { error: 0 }, successful: true },
        { label: "error-empty", fields: { error: "" }, successful: true },
        { label: "error-array", fields: { error: [] }, successful: false },
        { label: "error-object", fields: { error: {} }, successful: false },
        { label: "error-text", fields: { error: "provider failure" }, successful: false },
        { label: "error-number", fields: { error: 1 }, successful: false },
        { label: "error-true", fields: { error: true }, successful: false },
        { label: "health-error", fields: { health: "error" }, successful: false },
        { label: "health-stale", fields: { health: "stale" }, successful: false },
        { label: "source-error", fields: { source: "error" }, successful: false },
        { label: "source-stale", fields: { source: "stale" }, successful: false },
        { label: "stale-true", fields: { stale: true }, successful: false },
        { label: "stale-text", fields: { stale: "true" }, successful: true },
        { label: "stale-number", fields: { stale: 1 }, successful: true },
      ];
      const candidateIds: number[] = [];
      const latestIds: number[] = [];
      let successfulCount = 0;

      for (const testCase of cases) {
        const credential = fixture.createCredential(owner.id, testCase.label);
        const candidate = fixture.insert(owner.id, credential, cutoff - 2 * DAY, testCase.fields);
        const latest = fixture.insert(owner.id, credential, cutoff - DAY, {
          error: "latest provider failure",
          health: "error",
          source: "error",
          stale: true,
          limits: [],
        });
        candidateIds.push(candidate);
        latestIds.push(latest);
        if (testCase.successful) successfulCount += 1;
        expect(fixture.vault.getLastSuccessfulUsage(owner.id, credential)?.fetchedAt ?? null)
          .toBe(testCase.successful ? cutoff - 2 * DAY : null);
        expect(fixture.vault.getLastSuccessfulUsageInternal(credential)?.fetchedAt ?? null)
          .toBe(testCase.successful ? cutoff - 2 * DAY : null);
      }

      const receipt = await fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
      expect(receipt.protectedCount).toBe(cases.length + successfulCount);
      expect(receipt.deletedCount).toBe(cases.length - successfulCount);
      expect(fixture.snapshotIds().sort((a, b) => a - b)).toEqual([
        ...latestIds,
        ...cases.flatMap((testCase, index) => testCase.successful ? [candidateIds[index]!] : []),
      ].sort((a, b) => a - b));
    } finally {
      fixture.close();
    }
  });

  it("skips malformed and null legacy JSON without losing the last readable success", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = fixture.createUser("retention-malformed");
      const credential = fixture.createCredential(owner.id, "Legacy JSON");
      const lastGood = fixture.insert(owner.id, credential, cutoff - 4 * DAY, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      const nullReport = fixture.insert(owner.id, credential, cutoff - 3 * DAY, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      fixture.setReportJson(nullReport, "null");
      const malformedOlder = fixture.insert(owner.id, credential, cutoff - 2 * DAY, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      fixture.setReportJson(malformedOlder, "{malformed");
      const malformedLatest = fixture.insert(owner.id, credential, cutoff - DAY, {
        health: "healthy",
        source: "live",
        stale: false,
      });
      fixture.setReportJson(malformedLatest, "{also-malformed");

      expect(fixture.vault.getLastSuccessfulUsage(owner.id, credential)?.fetchedAt)
        .toBe(cutoff - 4 * DAY);
      const receipt = await fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
      expect(receipt.protectedCount).toBe(2);
      expect(receipt.deletedCount).toBe(2);
      expect(fixture.snapshotIds().sort((a, b) => a - b)).toEqual([lastGood, malformedLatest]);
    } finally {
      fixture.close();
    }
  });

  it("keeps expired-time inserts beyond the starting watermark for the next run", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = fixture.createUser("retention-watermark");
      const credential = fixture.createCredential(owner.id, "Watermark account");
      fixture.insertManyErrors(owner.id, credential, 1_002, cutoff - 5_000);
      const initialIds = fixture.snapshotIds();
      const initialLatestId = initialIds[initialIds.length - 1]!;
      let lateWriteId = 0;

      vi.useFakeTimers();
      try {
        const lateInsert = new Promise<void>(resolve => {
          setTimeout(() => {
            fixture.vault.saveUsageSnapshot(owner.id, {
              ownerId: owner.id,
              provider: PROVIDER,
              credentialId: credential,
              accountLabel: "Watermark account",
              fetchedAt: cutoff - 6_000,
              limits: [],
              error: "late expired insertion",
              health: "error",
              source: "error",
            });
            const row = fixture.db.prepare(`
              SELECT id FROM usage_snapshots ORDER BY id DESC LIMIT 1
            `).get() as { id: number };
            lateWriteId = row.id;
            resolve();
          }, 0);
        });
        const pruning = fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
        vi.advanceTimersByTime(0);
        await Promise.resolve();
        await lateInsert;
        vi.advanceTimersByTime(0);
        await Promise.resolve();
        const firstReceipt = await pruning;
        expect(firstReceipt.watermark).toBe(initialLatestId);
        expect(firstReceipt.deletedCount).toBe(1_001);
        expect(firstReceipt.batches).toBe(2);
        expect(lateWriteId).toBeGreaterThan(firstReceipt.watermark);
        expect(fixture.snapshotIds().sort((a, b) => a - b)).toEqual([initialLatestId, lateWriteId]);

        const secondPruning = fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
        vi.advanceTimersByTime(0);
        await Promise.resolve();
        const secondReceipt = await secondPruning;
        expect(secondReceipt.watermark).toBe(lateWriteId);
        expect(secondReceipt.deletedCount).toBe(1);
        expect(fixture.snapshotIds()).toEqual([initialLatestId]);
      } finally {
        vi.useRealTimers();
      }

    } finally {
      fixture.close();
    }
  });

  it("releases temporary state after a delete failure and allows the next prune", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = fixture.createUser("retention-failure");
      const credential = fixture.createCredential(owner.id, "Failure account");
      fixture.insert(owner.id, credential, cutoff - 2 * DAY, {
        error: "old failure",
        health: "error",
        source: "error",
        limits: [],
      });
      fixture.insert(owner.id, credential, cutoff - DAY, {
        error: "latest failure",
        health: "error",
        source: "error",
        limits: [],
      });
      fixture.db.exec(`
        CREATE TRIGGER reject_retention_delete
        BEFORE DELETE ON usage_snapshots
        BEGIN
          SELECT RAISE(ABORT, 'injected retention failure');
        END;
      `);

      let failure: unknown;
      try {
        await fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(Error);
      expect(fixture.snapshotIds()).toHaveLength(2);

      fixture.db.exec("DROP TRIGGER reject_retention_delete;");
      const recovery = await fixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
      expect(recovery.deletedCount).toBe(1);
      expect(fixture.snapshotIds()).toHaveLength(1);
    } finally {
      fixture.close();
    }
  });

  it("honors abort and close between batches without using a closed database", async () => {
    const abortFixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = abortFixture.createUser("retention-abort");
      const credential = abortFixture.createCredential(owner.id, "Abort account");
      abortFixture.insertManyErrors(owner.id, credential, 1_002, cutoff - 5_000);
      vi.useFakeTimers();
      try {
        const controller = new AbortController();
        const pruning = abortFixture.vault.pruneUsageSnapshots({
          retentionDays: 7,
          now,
          signal: controller.signal,
        });
        controller.abort();
        vi.advanceTimersByTime(0);
        await Promise.resolve();
        let abortError: unknown;
        try {
          await pruning;
        } catch (error) {
          abortError = error;
        }
        expect(abortError).toMatchObject({ name: "AbortError" });

        const recovery = abortFixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
        vi.advanceTimersByTime(0);
        await Promise.resolve();
        await expect(recovery).resolves.toMatchObject({ deletedCount: 1 });
      } finally {
        vi.useRealTimers();
      }
    } finally {
      abortFixture.close();
    }

    const closeFixture = createFixture();
    try {
      const now = Date.now();
      const cutoff = now - 7 * DAY;
      const owner = closeFixture.createUser("retention-close");
      const credential = closeFixture.createCredential(owner.id, "Close account");
      closeFixture.insertManyErrors(owner.id, credential, 1_002, cutoff - 5_000);
      vi.useFakeTimers();
      try {
        const pruning = closeFixture.vault.pruneUsageSnapshots({ retentionDays: 7, now });
        closeFixture.closeVault();
        vi.advanceTimersByTime(0);
        await Promise.resolve();
        const receipt = await pruning;
        expect(receipt.stopped).toBe("closed");
        expect(closeFixture.db.prepare("SELECT COUNT(*) AS count FROM usage_snapshots").get())
          .toMatchObject({ count: 2 });
      } finally {
        vi.useRealTimers();
      }
    } finally {
      closeFixture.close();
    }
  });

  it("starts an immediate default seven-day prune and stops its timer/work cleanly", async () => {
    const fixture = createFixture();
    try {
      const now = Date.now();
      const owner = fixture.createUser("retention-startup");
      const credential = fixture.createCredential(owner.id, "Startup account");
      fixture.insertManyErrors(owner.id, credential, 1_002, now - 9 * DAY);

      const retention = new UsageSnapshotRetention(fixture.vault);
      const receipt = await retention.start();
      expect(receipt.deletedCount).toBe(1_001);
      expect(receipt.protectedCount).toBe(1);
      expect(fixture.snapshotIds()).toHaveLength(1);
      await retention.stop();
      await retention.stop();
    } finally {
      fixture.close();
    }

    const stopFixture = createFixture();
    try {
      const now = Date.now();
      const owner = stopFixture.createUser("retention-stop");
      const credential = stopFixture.createCredential(owner.id, "Stop account");
      stopFixture.insertManyErrors(owner.id, credential, 1_002, now - 9 * DAY);
      const retention = new UsageSnapshotRetention(stopFixture.vault);
      const initialRun = retention.start();
      await retention.stop();
      let stopError: unknown;
      try {
        await initialRun;
      } catch (error) {
        stopError = error;
      }
      expect(stopError).toMatchObject({ name: "AbortError" });
      const recovered = await stopFixture.vault.pruneUsageSnapshots();
      expect(recovered.deletedCount).toBe(1);
      expect(stopFixture.snapshotIds()).toHaveLength(1);
    } finally {
      stopFixture.close();
    }
  });
});

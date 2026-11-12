import { assertMasterKeyConfigured } from "./core/crypto";
import { DEFAULT_USAGE_SNAPSHOT_RETENTION_DAYS, StorageVault } from "./core/storage/vault";
import { UsageSnapshotRetention } from "./core/storage/retention";
import { createDefaultRegistry } from "./core/providers/registry";
import { PollerEngine } from "./core/poller/poller";
import type { PollerOptions } from "./core/poller/poller";
import { AuthService } from "./core/auth/auth";
import { createUnixPasswordResetMailer } from "./core/auth/password-reset-mailer";
import { AlertEvaluator, NotificationDispatcher } from "./core/notifier";
import { createServer } from "./server/app";

// Fail early in production if encryption key is insecure or absent
assertMasterKeyConfigured();

const port = Number(process.env["PORT"]) || 3100;
const dbPath = process.env["DATABASE_PATH"] || "data/usage.db";

const retentionDaysSetting = process.env["SNAPSHOT_RETENTION_DAYS"];
const snapshotRetentionDays = retentionDaysSetting === undefined
  ? DEFAULT_USAGE_SNAPSHOT_RETENTION_DAYS
  : Number(retentionDaysSetting.trim());
if (
  !Number.isSafeInteger(snapshotRetentionDays) ||
  snapshotRetentionDays < 1 ||
  !Number.isSafeInteger(snapshotRetentionDays * 24 * 60 * 60 * 1_000)
) {
  throw new RangeError("SNAPSHOT_RETENTION_DAYS must be a positive safe integer.");
}

const vault = new StorageVault(dbPath);
const registry = createDefaultRegistry();
const pollTimeoutMs = process.env["POLL_TIMEOUT_MS"] === undefined
  ? undefined
  : Number(process.env["POLL_TIMEOUT_MS"]);
const poller = new PollerEngine(vault, registry, {
  pollTimeoutMs,
  maxConcurrentGlobal: process.env["POLL_MAX_CONCURRENT_GLOBAL"] === undefined
    ? undefined
    : Number(process.env["POLL_MAX_CONCURRENT_GLOBAL"]),
  maxConcurrentPerProvider: process.env["POLL_MAX_CONCURRENT_PER_PROVIDER"] === undefined
    ? undefined
    : Number(process.env["POLL_MAX_CONCURRENT_PER_PROVIDER"]),
  minProviderIntervalMs: process.env["POLL_MIN_PROVIDER_INTERVAL_MS"] === undefined
    ? undefined
    : Number(process.env["POLL_MIN_PROVIDER_INTERVAL_MS"]),
  maxQueuedJobs: process.env["POLL_MAX_QUEUED_JOBS"] === undefined
    ? undefined
    : Number(process.env["POLL_MAX_QUEUED_JOBS"]),
  admissionTimeoutMs: process.env["POLL_ADMISSION_TIMEOUT_MS"] === undefined
    ? undefined
    : Number(process.env["POLL_ADMISSION_TIMEOUT_MS"]),
} satisfies PollerOptions);

// Start background polling daemon
poller.start();

// Initialize notification dispatcher & alert evaluator
const notificationDispatcher = new NotificationDispatcher();
const alertEvaluator = new AlertEvaluator(vault, notificationDispatcher);
poller.onReport((report) => {
  void alertEvaluator.evaluateReport(report).catch((error: unknown) => {
    console.error("Alert evaluation failed:", error);
  });
});

const snapshotRetention = new UsageSnapshotRetention(vault, {
  retentionDays: snapshotRetentionDays,
});
void snapshotRetention.start().catch((error: unknown) => {
  if (error instanceof Error && error.name === "AbortError") return;
  console.error("Usage snapshot retention failed:", error);
});

const recoveryMailSocket = process.env["RECOVERY_MAIL_SOCKET"]?.trim();
const authService = new AuthService(
  vault,
  recoveryMailSocket
    ? { passwordResetMailer: createUnixPasswordResetMailer(recoveryMailSocket) }
    : {},
);
const app = createServer(vault, poller, registry, authService);

console.log(`⚡ useMeter started at http://localhost:${port}`);

export default {
  port,
  fetch: app.fetch,
};

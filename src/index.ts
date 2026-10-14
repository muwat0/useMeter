import { assertMasterKeyConfigured } from "./core/crypto";
import { StorageVault } from "./core/storage/vault";
import { createDefaultRegistry } from "./core/providers/registry";
import { PollerEngine } from "./core/poller/poller";
import type { PollerOptions } from "./core/poller/poller";
import { AuthService } from "./core/auth/auth";
import { createServer } from "./server/app";

// Fail early in production if encryption key is insecure or absent
assertMasterKeyConfigured();

const port = Number(process.env["PORT"]) || 3100;
const dbPath = process.env["DATABASE_PATH"] || "data/usage.db";

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

const authService = new AuthService(vault);
const app = createServer(vault, poller, registry, authService);

console.log(`⚡ useMeter started at http://localhost:${port}`);

export default {
  port,
  fetch: app.fetch,
};

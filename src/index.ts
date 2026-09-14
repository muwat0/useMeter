import { assertMasterKeyConfigured } from "./core/crypto";
import { StorageVault } from "./core/storage/vault";
import { createDefaultRegistry } from "./core/providers/registry";
import { PollerEngine } from "./core/poller/poller";
import { AuthService } from "./core/auth/auth";
import { createServer } from "./server/app";

// Fail early in production if encryption key is insecure or absent
assertMasterKeyConfigured();

const port = Number(process.env["PORT"]) || 3100;
const dbPath = process.env["DATABASE_PATH"] || "data/usage.db";

const vault = new StorageVault(dbPath);
const registry = createDefaultRegistry();
const poller = new PollerEngine(vault, registry);

// Start background polling daemon
poller.start();

const authService = new AuthService(vault);
const app = createServer(vault, poller, registry, authService);

console.log(`⚡ useMeter started at http://localhost:${port}`);

export default {
  port,
  fetch: app.fetch,
};

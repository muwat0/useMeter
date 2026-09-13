import { StorageVault } from "./core/storage/vault";
import { createDefaultRegistry } from "./core/providers/registry";
import { PollerEngine } from "./core/poller/poller";
import { createServer } from "./server/app";

const port = Number(process.env["PORT"]) || 3100;
const dbPath = process.env["DATABASE_PATH"] || "data/usage.db";

const vault = new StorageVault(dbPath);
const registry = createDefaultRegistry();
const poller = new PollerEngine(vault, registry);

// Start background polling daemon
poller.start();

const app = createServer(vault, poller, registry);

console.log(`⚡ AI Usage Tracker started at http://localhost:${port}`);

export default {
  port,
  fetch: app.fetch,
};

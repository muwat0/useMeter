# Docker Deployment Guide

useMeter is a Bun HTTP service with SQLite persistence. It is **not** deployable by uploading `dist/client` into ReverseProxy's `my_webapp`: that app serves static/PHP files and does not run Bun, SQLite migrations, polling, or OAuth callback routes.

## Required server prerequisites

Ensure the host system provides:

- Docker Engine and Docker Compose v2
- Docker access for the deployment account, or an administrator-run deployment
- A writable deployment directory, for example `/opt/usemeter`
- A persistent Docker volume for `/app/data`
- A domain or subdomain, for example `usemeter.example.com`
- A reverse proxy route from that domain to `127.0.0.1:3100`
- A production `USAGE_MASTER_KEY` stored outside the repository

The deployment on `production-server` is active: Docker Engine 29.8.0 runs the container through ReverseProxy's `reverseproxy` app at `usemeter.example.com`. The site uses a Let's Encrypt certificate and the deployment directory is `/opt/usemeter`; the Compose named volume is `usemeter-data`. The service binds only to `127.0.0.1:3100`.

## Install

From the deployment directory:

> **Existing-database safety gate:** A release containing automatic snapshot retention performs a prune on its first application startup. Before the first `docker compose up -d` against an existing data volume, create and verify a standalone, WAL-consistent backup of the current database. The direct-SQLite `VACUUM INTO` pattern below is one supported method; apply the schema, integrity, and count checks appropriate to the current database. Retain the copy outside the live volume. Reverting the application image alone cannot restore snapshots already deleted by retention.

```sh
git clone https://github.com/muwat0/useMeter.git .
# Or fetch the desired release commit from the canonical repository.

export USAGE_MASTER_KEY='generate-a-long-random-secret'
docker compose build
docker compose up -d
```

Do not commit `.env` or the master key. For repeatable deployments, use a root-readable environment file outside the checkout and pass it with Compose's `--env-file` option.

## Verify

```sh
curl --fail http://127.0.0.1:3100/health
# Expected JSON includes: {"status":"ok","integrity":true}

docker compose ps
docker compose logs --tail=100 usemeter
```

The dashboard is served at `/`; static bundles `/assets/app.js` and `/assets/app.css` are content-addressed in the HTML (`?v=<digest>`) with immutable 1-year caching so new deployments invalidate client cache automatically. The SQLite database lives in the named `usemeter-data` volume at `/app/data/usage.db`.

## Reverse proxy

Configure your reverse proxy to proxy the selected HTTPS domain to `127.0.0.1:3100`. Preserve the `Host`, `X-Forwarded-For`, and `X-Forwarded-Proto` headers. Set `TRUST_PROXY=true` only when the proxy path is controlled and these headers cannot be spoofed by direct public access.

The application already emits security headers and uses conditional HSTS. Keep TLS termination at the reverse proxy and do not expose port 3100 publicly; the Compose file binds it to loopback by default.

## Optional rootless password recovery mail bridge (source capability; host setup pending)

The checked-in base `compose.yaml` forwards `RECOVERY_MAIL_SOCKET` with an empty default. With no helper socket configured, new password-reset requests return `503 RECOVERY_UNAVAILABLE`; the application does not create a log-only/fake delivery. A previously issued, still-valid reset token remains consumable after the sender is disabled.

To enable the optional source overlay, prepare a **dedicated persistent host directory** for the socket and configure the host helper before recreating the container:

- `deploy/compose.mail.yaml` mounts only `${MAIL_BRIDGE_HOST_DIR:-/opt/usemeter/mail}` at `/app/mail-bridge:ro`, adds `${MAIL_BRIDGE_HOST_GID:-1000}` to the container group list, and sets the app socket path to `/app/mail-bridge/bridge.sock`. The app container runs as UID 1000. The host directory must remain stable across service restarts; the helper recreates only the socket file. Do not mount the user's home directory, runtime/session directories, or the host filesystem.
- The directory must be owned by the service user, mode `0770`, and use the same group ID as `MAIL_BRIDGE_HOST_GID` / helper `SOCKET_GROUP_ID`. The socket is mode `0660`; never relax either to world-writable. On the verified host the dedicated group ID is `1000`; select matching IDs on other systems.
- Copy `deploy/mail-helper/mail-bridge.env.example` to `~/.config/usemeter/mail-bridge.env`, owned by the service user with mode `0600` in a private configuration directory. Set mandatory `PUBLIC_ORIGIN` to the canonical HTTPS origin only (no path, query, fragment, or trailing slash) and `MAIL_SENDER` to the operator-controlled sender. The example also supplies `ALLOWED_PEER_UIDS`, `SOCKET_GROUP_ID`, and `SENDMAIL_BIN`; the default sendmail path is `/usr/sbin/sendmail`.
- Install/run `deploy/mail-helper/usemeter-mail-bridge.service` as the same unprivileged host user with `systemctl --user daemon-reload` and `systemctl --user enable --now usemeter-mail-bridge.service`. Its `EnvironmentFile` is mandatory. Its `ExecStart` expects the checkout at `%h/useMeter-deploy`; if the source lives elsewhere, point that unit directive at the actual helper path. A user service that must survive logout/reboot needs user lingering enabled.
- The helper accepts only a newline-delimited JSON object with `recipient` and a 64-lowercase-hex `token`; peer UID is checked using `SO_PEERCRED`. It creates `/reset-password#token=...` using the fixed origin and invokes the configured sendmail argv as `sendmail -oi -f <sender> -- <recipient>` without a shell. It does not expose a generic command/mail interface or require SMTP credentials.
- **Keep the sandbox distinction:** the useMeter container keeps Compose's `no-new-privileges:true`. Do not enable `NoNewPrivileges=true` on the rootless mail helper unit: standard `/usr/sbin/sendmail` invokes setgid `postdrop` to submit to Postfix's local maildrop, and the unit documents why that transition must remain available. Do not add root privileges, alter MTA network/authentication policy, or install a human SMTP password.

The helper/client have a local IPC smoke test using a synthetic sendmail sink and no network or real email; it covers strict framing, peer rejection, reconnect after helper restart, and abort/stop descendant cleanup. This is not proof of host MTA acceptance, mailbox delivery, or a delivered DKIM signature. Host provisioning, socket/mount permission checks, helper restart reconnection, and a real message to a disposable owned mailbox are still required before claiming recovery delivery is operational. This source documentation does not assert that the production Compose file or running service currently has the overlay enabled.

## Updates and rollback

### Two-phase deployment & single-writer target SOP

The production deployment runs from `/opt/usemeter` with Compose file `/opt/usemeter/compose.yaml` and persistent named volume `usemeter-data`. The deployment directory is not a Git checkout; application bundles and images are staged and built from source before deployment.

**CRITICAL SAFETY RULES:**
- **NEVER** use `docker compose down`, `-v` (volume deletion), or `docker system prune` on the deployment host. `down` stops unrelated stack services and risks volume detachment or loss. Always target only the `usemeter` service directly.
- **Single-writer stop:** Always stop the existing container with `docker compose stop usemeter` before recreating or switching image tags to prevent concurrent SQLite write contention.
- **Irreversibility of v2 encryption:** Once migrated to `PRAGMA user_version = 2`, v2 metadata encryption **cannot be disabled** via environment variables (`CREDENTIAL_METADATA_ENCRYPTION`). The vault checks `schemaVersion >= 2` and strictly enforces fail-closed encrypted envelopes.

#### Current phase-1 state and rollback pin
- Production currently runs the healthy dual-reader image `usemeter:release-4-phase1`, image digest `sha256:177be07af5ccc27610c9a9535bf611b9cf021aabb87902542f71d18b840998ca`. Preserve this exact image/tag as the rollback target; never retarget the tag.
- The live database remains `PRAGMA user_version = 1`; `CREDENTIAL_METADATA_ENCRYPTION` is absent from the running service. The dated backup noted in earlier deployment records is historical only: phase 2 requires a fresh, verified pre-v2 backup as described below.

#### Phase 1 (dual-reader image)
Phase 1 is already live. Its image understands legacy plaintext metadata and v2 envelopes, but the production database remains v1 until the offline phase-2 migration below. Do not add or enable the encryption setting during phase 1.

#### Phase 2 (offline v2 migration and cutover)
Perform these steps in order. **Do not start or recreate the application until every offline migration and backup gate passes.** `src/index.ts` starts the poller on boot; it must not run during migration.

1. **Stage and build while phase 1 serves traffic.** Stage the complete reviewed release source and checked-in `compose.yaml` service mapping:
   ```yaml
   CREDENTIAL_METADATA_ENCRYPTION: ${CREDENTIAL_METADATA_ENCRYPTION:-enabled}
   ```
   This explicitly forwards the setting into the service container. Do not start the new image yet. Build only the target service; this does not mount or modify the database:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml build usemeter
   ```
2. **Stop the sole SQLite writer.** Stop only `usemeter` and leave the other stack services, volume, and database files untouched:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml stop usemeter
   ```
3. **Create and verify a fresh pre-v2 backup.** With the writer stopped, use a one-shot Bun process with a direct `bun:sqlite` connection to `/app/data/usage.db`; create a standalone WAL-consistent backup with SQLite `VACUUM INTO` (or SQLite's backup API). Do **not** instantiate `StorageVault` for this backup (instantiating it under an enabled environment would trigger migration prematurely), and do not copy only `usage.db` while WAL may contain committed data. Set `process.umask(0o077)` before `VACUUM INTO` so the backup file is created with restricted permissions and never briefly appears mode `0644`, followed by `chmodSync(dest, 0o600)` as defense-in-depth:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'process.umask(0o077); const { Database } = await import("bun:sqlite"); const fs = await import("node:fs"); const dest = `/app/data/pre-v2-backup-${Date.now()}.sqlite`; const db = new Database(process.env.DATABASE_PATH || "/app/data/usage.db"); db.exec(`VACUUM INTO "${dest}"`); db.close(); fs.chmodSync(dest, 0o600); console.log(dest);'
   ```
   Stream the backup TAR from the stopped one-shot container to the host and extract as `murat` with a restrictive umask. Use the exact unique filename printed above; do not use `sudo` for `tar`:
   ```sh
   umask 077
   set -o pipefail
   sudo -n /usr/bin/docker cp usemeter-deploy-usemeter-1:/app/data/<unique-backup-filename> - | tar --no-same-owner --no-same-permissions -xf - -C ${HOME}/usemeter-backups/
   ```
   Verify the retained host file itself before proceeding. First capture source `user_version`, integrity, credentials, and snapshot counts from the volume using a one-shot direct `bun:sqlite` check; print only those values, never metadata. Then run this unprivileged read-only check on the host backup:
   ```sh
   python3 -c 'import hashlib, os, sqlite3, sys; p=sys.argv[1]; s=os.stat(p); assert s.st_uid == os.getuid() and (s.st_mode & 0o777) == 0o600, "backup owner/mode check failed"; db=sqlite3.connect("file:" + os.path.realpath(p) + "?mode=ro", uri=True); v=db.execute("PRAGMA user_version").fetchone()[0]; q=db.execute("PRAGMA quick_check").fetchone()[0]; i=db.execute("PRAGMA integrity_check").fetchone()[0]; c=db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]; u=db.execute("SELECT COUNT(*) FROM usage_snapshots").fetchone()[0]; db.close(); assert v == 1 and q == "ok" and i == "ok", "backup schema/integrity check failed"; print({"user_version": v, "quick_check": q, "integrity_check": i, "credentials": c, "snapshots": u, "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(), "owner_mode_ok": True})' ${HOME}/usemeter-backups/<unique-backup-filename>
   ```
   Require owner `murat`, mode `0600`, `user_version = 1`, both integrity checks `ok`, and matching credentials/snapshot counts and SHA256 with the recorded source/baseline. *(If host Python 3 is absent, verify via a read-only bind mount: `sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps -v ${HOME}/usemeter-backups:/backups:ro --entrypoint bun usemeter -e '...'`)*. If any check fails, do not migrate or delete the temporary backup. After all host-copy checks pass, remove ONLY that unique temporary backup inside `/app/data` (never touch `usage.db`, `usage.db-wal`, or `usage.db-shm`):
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'import fs from "node:fs"; const target = "/app/data/<unique-backup-filename>"; if (target.startsWith("/app/data/pre-v2-backup-") && fs.existsSync(target)) fs.unlinkSync(target);'
   ```
   Keep the host plaintext-metadata backup protected; migration does not erase old backups.
4. **Migrate offline using the new image, without application startup.** Confirm the staged Compose file retains the service environment mapping above. Run a one-shot Compose service process that inherits that service environment and volume, overrides the image entrypoint to Bun, and imports only `StorageVault`; do not invoke `src/index.ts`, HTTP serving, or the poller:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'if (process.env.CREDENTIAL_METADATA_ENCRYPTION !== "enabled") throw new Error("encryption setting is not enabled"); console.log(process.env.CREDENTIAL_METADATA_ENCRYPTION === "enabled"); const { StorageVault } = await import("./src/core/storage/vault"); const vault = new StorageVault(process.env.DATABASE_PATH || "/app/data/usage.db"); vault.close();'
   ```
   The only environment-related output must be `true`; this checks the effective Boolean without printing other environment values. If it is not `true`, or the one-shot command fails, do not start the application.
5. **Checkpoint and compact while still offline.** Use a second direct `bun:sqlite` one-shot against the same volume to run `PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);`. Do not start the application between migration and verification:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'import { Database } from "bun:sqlite"; const db = new Database(process.env.DATABASE_PATH || "/app/data/usage.db"); db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);"); db.close();'
   ```
6. **Verify migration and take the v2 backup.** Using a one-shot container with direct SQLite inspection (never print metadata values, never access `/var/lib/docker/volumes` directly on the host), require all verification gates:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'import { Database } from "bun:sqlite"; const db = new Database(process.env.DATABASE_PATH || "/app/data/usage.db"); const v = Object.values(db.prepare("PRAGMA user_version").get())[0]; const qc = Object.values(db.prepare("PRAGMA quick_check").get())[0]; const ic = Object.values(db.prepare("PRAGMA integrity_check").get())[0]; let nonV2 = 0; for (const { metadata } of db.prepare("SELECT metadata FROM credentials WHERE metadata IS NOT NULL").all()) { try { const x = JSON.parse(metadata); const keys = x && typeof x === "object" && !Array.isArray(x) ? Object.keys(x) : []; if (x?.["$vault"] !== 1 || keys.length !== 4 || !["$vault", "ciphertext", "iv", "tag"].every((k) => keys.includes(k)) || typeof x.ciphertext !== "string" || !/^(?:[0-9a-f]{2})*$/i.test(x.ciphertext) || typeof x.iv !== "string" || !/^[0-9a-f]{24}$/i.test(x.iv) || typeof x.tag !== "string" || !/^[0-9a-f]{32}$/i.test(x.tag)) nonV2++; } catch { nonV2++; } } const creds = db.prepare("SELECT COUNT(*) as c FROM credentials").get().c; const snaps = db.prepare("SELECT COUNT(*) as c FROM usage_snapshots").get().c; console.log({ user_version: v, quick_check: qc, integrity_check: ic, non_v2_metadata: nonV2, credentials: creds, snapshots: snaps }); db.close();'
   ```
   Require `user_version: 2`, `quick_check: "ok"`, `integrity_check: "ok"`, `non_v2_metadata: 0`, and credential and snapshot counts at least their recorded pre-migration baselines.
   If any gate fails, stop here and use the phase-1 dual-reader rollback below. If all pass, create a standalone WAL-consistent v2 backup inside the volume with direct SQLite `VACUUM INTO` (not `StorageVault`), setting `process.umask(0o077)` beforehand and `chmodSync(dest, 0o600)` afterward:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'process.umask(0o077); const { Database } = await import("bun:sqlite"); const fs = await import("node:fs"); const dest = `/app/data/v2-backup-${Date.now()}.sqlite`; const db = new Database(process.env.DATABASE_PATH || "/app/data/usage.db"); db.exec(`VACUUM INTO "${dest}"`); db.close(); fs.chmodSync(dest, 0o600); console.log(dest);'
   ```
   Stream the v2 backup TAR to the host and extract as `murat` under `umask 077`:
   ```sh
   umask 077
   set -o pipefail
   sudo -n /usr/bin/docker cp usemeter-deploy-usemeter-1:/app/data/<unique-v2-backup-filename> - | tar --no-same-owner --no-same-permissions -xf - -C ${HOME}/usemeter-backups/
   ```
   Verify the retained host v2 backup itself before proceeding (owner `murat`, mode `0600`, `user_version = 2`, integrity `ok`, counts nondecreasing):
   ```sh
   python3 -c 'import hashlib, os, sqlite3, sys; p=sys.argv[1]; s=os.stat(p); assert s.st_uid == os.getuid() and (s.st_mode & 0o777) == 0o600, "backup owner/mode check failed"; db=sqlite3.connect("file:" + os.path.realpath(p) + "?mode=ro", uri=True); v=db.execute("PRAGMA user_version").fetchone()[0]; q=db.execute("PRAGMA quick_check").fetchone()[0]; i=db.execute("PRAGMA integrity_check").fetchone()[0]; c=db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]; u=db.execute("SELECT COUNT(*) FROM usage_snapshots").fetchone()[0]; db.close(); assert v == 2 and q == "ok" and i == "ok", "v2 backup schema/integrity check failed"; print({"user_version": v, "quick_check": q, "integrity_check": i, "credentials": c, "snapshots": u, "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(), "owner_mode_ok": True})' ${HOME}/usemeter-backups/<unique-v2-backup-filename>
   ```
   *(If host Python 3 is absent, verify via a read-only bind mount: `sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps -v ${HOME}/usemeter-backups:/backups:ro --entrypoint bun usemeter -e '...'`)*.
   Only after the retained host v2 backup passes all verification checks, remove ONLY that unique temporary backup inside `/app/data` (never touch `usage.db`, `usage.db-wal`, or `usage.db-shm`):
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml run --rm --no-deps --entrypoint bun usemeter -e 'import fs from "node:fs"; const target = "/app/data/<unique-v2-backup-filename>"; if (target.startsWith("/app/data/v2-backup-") && fs.existsSync(target)) fs.unlinkSync(target);'
   ```
   This host backup contains encrypted metadata; retain it securely. Existing protected plaintext backups remain and must not be represented as erased.
7. **Start the application only after all gates and the verified v2 backup succeed.** Recreate only the `usemeter` service:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml up -d --no-build --no-deps --force-recreate usemeter
   ```
   Verify the effective setting without printing any other environment values:
   ```sh
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml exec -T usemeter bun -e 'console.log(process.env["CREDENTIAL_METADATA_ENCRYPTION"] === "enabled")'
   ```
   Require `true`, verify `/health` reports `{"status":"ok","integrity":true}`, and verify the database remains at `user_version = 2`. If startup or health checks fail, stop only `usemeter` and use the phase-1 dual-reader rollback; do not restore a v1 database as an improvised fix.

Never run `docker compose down`, `-v`, `docker system prune`, a root shell, or any unapproved privileged command. Keep the `usemeter-data` named volume attached throughout; never restore by copying only the main SQLite file.

### Version-tag deployment and rollback standard

Starting with `v1.0.0`, all Docker image tags, release archives, and rollback pins follow semantic versioning instead of ephemeral commit hashes:

1. **Release Archive:**
   - Named `usemeter-<tag>.tar.gz` (e.g. `usemeter-v1.0.0.tar.gz`).
   - Generated directly from the annotated git tag:
     ```sh
     git archive --format=tar.gz -o usemeter-v1.0.0.tar.gz v1.0.0
     ```

2. **Docker Image Tags:**
   - Every release image built on the host is tagged with its SemVer tag:
     `usemeter:vX.Y.Z` (e.g. `usemeter:v1.0.0`).
   - In addition, convenience pointers `usemeter:latest` and `usemeter:local` are tagged to point to the current active release.
   ```sh
   sudo -n /usr/bin/docker image tag usemeter:local usemeter:v1.0.0
   sudo -n /usr/bin/docker image tag usemeter:local usemeter:latest
   ```

3. **Standard Rollback Pin Naming:**
   - Before applying a new release `vX.Y.Z`, the active running image is pinned as:
     `usemeter:rollback-pre-vX.Y.Z` (e.g. `usemeter:rollback-pre-v1.0.0`).
   - In addition, previous release images remain preserved as immutable version tags `usemeter:v<PREVIOUS_VERSION>` (e.g. `usemeter:v1.0.0`).

4. **Instant Rollback Procedure:**
   To roll back to the pre-deployment state or any specific historical release:
   ```sh
   # Roll back to the immediately prior state:
   sudo -n /usr/bin/docker image tag usemeter:rollback-pre-vX.Y.Z usemeter:local

   # Or roll back to a specific version (e.g. v1.0.0):
   sudo -n /usr/bin/docker image tag usemeter:v1.0.0 usemeter:local

   # Restart the single service without touching the database volume:
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml stop usemeter
   sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml up -d --no-build --no-deps --force-recreate usemeter
   ```

### Historical Rollback Notes (Schema v1 -> v2)

The live database runs on `PRAGMA user_version = 2` with AES-256-GCM metadata encryption enforced. Older pre-dual-reader images must never be started against a v2 database.
## Operational notes

The deployment is live on `production-server`. Keep the production `.env` file and the named Docker volume outside Git. Do not replace the `my_webapp` application; it is unrelated static/PHP hosting. Updates should be performed by fetching a reviewed release, rebuilding the image, and restarting the Compose service while preserving the named volume.

## Automated secure backups and isolated restore drills

`deploy/backup/usemeter-backup.sh` is intended to run as the unprivileged `murat` account through a systemd **user** service. It starts a one-shot Compose container with the same persistent data volume and application image, but runs only the direct Bun SQLite snapshot helper; it does not start `src/index.ts`, `StorageVault`, or the poller. SQLite `VACUUM INTO` creates a standalone snapshot from a consistent WAL view while the application remains the sole normal writer. The script never copies `usage.db` alone or explicitly issues `wal_checkpoint` or in-place `VACUUM` against the live path; SQLite coordinates WAL access and leaves the source database's logical contents unchanged.

The one-shot snapshot is written temporarily inside `/app/data` with `umask 077`, checked for `user_version = 2`, `quick_check = 'ok'`, and `integrity_check = 'ok'`, copied to the host as `murat`, and removed from the volume. The host backup directory is mode `0700`; each completed backup is mode `0600`. The copied candidate must also pass the isolated restore drill before it is promoted to its timestamped name. If the schema or integrity gates fail, the run fails closed.

The restore drill (`usemeter-restore-drill.sh BACKUP_FILE`) runs the candidate in a separate container with `--network none`, a read-only root filesystem, and only read-only bind mounts for the candidate and validator source. It has **no application data volume**, does not start the application, and cannot overwrite `/app/data/usage.db`. It verifies schema v2, both SQLite integrity checks, credential and snapshot counts, and the structure of every non-null encrypted metadata envelope (`$vault: 1`, ciphertext, IV, and tag). It does not decrypt credentials or prove provider authentication; it is a database restore-readiness check, not a production restore.

When invoked independently, the drill obtains its image digest from a running Compose service container. If no useMeter container is running, set `USEMETER_DRILL_IMAGE` to the exact `sha256:<64 lowercase hex>` ID of the already-built image; the drill still creates no app-data mount.

Retention keeps every backup from the last seven days, then the newest backup in each ISO week through age 28 days, and removes older generated backup files. A successful fresh backup and restore-drill result is required before pruning runs.

Install the reviewed helper files on the host as `murat` and copy the systemd units into the user unit directory:

```sh
install -d -m 0700 ~/.local/lib/usemeter/backup ~/.config/systemd/user
install -m 0700 deploy/backup/usemeter-backup.sh deploy/backup/usemeter-restore-drill.sh ~/.local/lib/usemeter/backup/
install -m 0644 deploy/backup/snapshot.ts deploy/backup/restore-drill.ts ~/.local/lib/usemeter/backup/
install -m 0644 deploy/backup/usemeter-backup.service deploy/backup/usemeter-backup.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now usemeter-backup.timer
```

The unit defaults expect the Compose project at `/opt/usemeter`, the file `compose.yaml`, the service `usemeter`, and backups under `${HOME}/usemeter-backups`. Override these with `USEMETER_PROJECT_DIR`, `USEMETER_COMPOSE_FILE`, `USEMETER_COMPOSE_SERVICE`, or `USEMETER_BACKUP_DIR` in `~/.config/usemeter/backup.env` if needed. Compose must read its protected interpolation environment (including `USAGE_MASTER_KEY`) to resolve the service configuration; the one-shot snapshot process overrides the master key and configured provider client secrets with empty values and never prints environment values. The timer runs daily at 03:30 UTC with up to five minutes of jitter. The user manager must remain active across logout/reboot (systemd lingering) for unattended runs. Inspect `systemctl --user status usemeter-backup.timer` and `journalctl --user -u usemeter-backup.service`; run the script manually as `murat` for an immediate backup.

```sh
BACKUP_FILE='${HOME}/usemeter-backups/REPLACE_WITH_TIMESTAMPED_BACKUP.sqlite'
~/.local/lib/usemeter/backup/usemeter-restore-drill.sh "$BACKUP_FILE"
```

Never restore a drill candidate by copying it over a live database. A real recovery remains an explicitly offline operation that stops the sole writer and follows the database-and-sidecar rollback rules above.

## Host health and disk notifications

`deploy/monitor/usemeter-monitor.py` is a standalone Python-standard-library monitor intended to run as the unprivileged deployment user. It does not connect to the application database, use an admin session, inspect accounts/providers, or change the running application. Each check directly requests the configured public `/health` URL (no proxy environment, redirects, cookies, or credentials) and measures the root filesystem through the user's home directory using `statvfs`. A health response is healthy only for HTTP 200 JSON with `status: "ok"`, `integrity: true`, and `pollerRunning: true`; the body is capped at 4 KiB and the full health request has a five-second deadline. Transfer-encoded responses are treated as unhealthy so malformed chunk lengths cannot bypass that bound. Disk alerting starts at `>= 90%` using `(blocks - bavail) / blocks`, matching the application metric.

The deployment timer checks every five minutes. Messages are deduplicated by the last alert set accepted by local sendmail, include only the public service URL and disk/health status, and are globally rate-limited to at most one automatic message per ten minutes. A changed condition remains pending until a successful sendmail submission; recovery is submitted after the cooldown if the condition remains clear. Before invoking sendmail, the monitor durably records an absolute pending-retry deadline. If that admission write exceeds its five-second budget, or the remaining bounded send window expires, the run fails closed without submitting mail. Only sendmail exit code 0 updates the accepted alert set. A failure before the mail process starts leaves the accepted alert set unchanged and retries after the ordinary cooldown; any ambiguous post-launch outcome retains the pending deadline and waits at least the ten-minute cooldown plus the five-second admission budget and ten-second sendmail timeout before reconciliation. If sendmail accepted a message but the post-acceptance state write failed or the process was interrupted, a later reconciliation can duplicate that message; the local queue and state file cannot be updated atomically. Once acceptance state is committed, delayed inbox receipt does not trigger retries. A healthy first check sends nothing. The monitor cannot report total host power loss or a network outage that prevents this same host from running; an independent external watcher is required for those failures.

Install the source separately from the application and do not use `sudo`:

```sh
mkdir -p -m 0700 ~/.local/lib/usemeter/monitor ~/.config/systemd/user
install -m 0700 deploy/monitor/usemeter-monitor.py ~/.local/lib/usemeter/monitor/
install -m 0644 deploy/monitor/usemeter-monitor.service deploy/monitor/usemeter-monitor.timer ~/.config/systemd/user/
```

Create `~/.config/usemeter` as the service user with mode `0700` if it does not already exist; verify rather than chmod an existing directory. Create `~/.config/usemeter/monitor.env` owned by that user with mode `0600`. Do not overwrite an existing configuration. Its strict, non-shell `KEY=value` format accepts only these settings:

```env
USEMETER_MONITOR_ENABLED=0
USEMETER_MONITOR_HEALTH_URL=https://usemeter.example.com/health
USEMETER_MONITOR_RECIPIENT=
USEMETER_MONITOR_SENDER=
```

The source default is delivery-disabled (`ENABLED=0`) with loopback health URL `http://127.0.0.1:3100/health`. For production, configure the actual public HTTPS URL shown above. Set the recipient and an operator-controlled sender address; automatic delivery remains disabled until both addresses are valid and `USEMETER_MONITOR_ENABLED=1`. The config file is read directly without shell evaluation. Per-process `USEMETER_MONITOR_*` environment values override file entries.

Run a real observation without sending or changing the last-submitted alert state. Output reports `wouldNotify` based on current observations, enabled configuration, and the stored local-MTA acceptance state:

```sh
/usr/bin/python3 ~/.local/lib/usemeter/monitor/usemeter-monitor.py --check-only
```

After the recipient and sender are set in the secure config, this shows whether the observed conditions differ from the accepted state while automatic delivery remains disabled. Temporarily override only that invocation; `--check-only` never sends or advances state:

```sh
USEMETER_MONITOR_ENABLED=1 /usr/bin/python3 ~/.local/lib/usemeter/monitor/usemeter-monitor.py --check-only
```

`--send-test` is a separate manual-only mode; the timer never invokes it. After configuring the approved recipient and sender, an operator may run it once to submit the fixed `[useMeter ops] Delivery test` message. Its body is exactly:

```text
This is the approved useMeter operational alert delivery test.
Service: https://usemeter.example.com
No account, credential, or usage data is included.
```

It does not write notification state. A successful command exit means the local sendmail interface accepted the message for submission; it does not establish inbox delivery. Confirm mailbox receipt independently. Mail receipt is never polled for automatic retry. Enable periodic notifications only after reviewing the configuration, completing check-only observation, and confirming the explicitly approved delivery test:

```sh
/usr/bin/python3 ~/.local/lib/usemeter/monitor/usemeter-monitor.py --send-test
systemctl --user daemon-reload
systemctl --user enable --now usemeter-monitor.timer
systemctl --user list-timers usemeter-monitor.timer
```

Inspect `journalctl --user -u usemeter-monitor.service` for sanitized status/error messages. The user systemd manager must remain active across logout/reboot (user lingering). The service has a 30-second execution bound and submits through `/usr/sbin/sendmail -oi -f <sender> -- <recipient>` without a shell; it stays unprivileged and does not grant Docker or sudo access. `NoNewPrivileges` and mount-namespace sandboxing are intentionally not enabled because the host's setgid `postdrop` handoff may otherwise fail, matching the existing rootless mail-bridge constraint.

The monitor stores only the last alert set accepted by local sendmail, its submission timestamp, and a private pending-attempt retry deadline in `~/.local/state/usemeter-monitor` (directory `0700`, files `0600`, umask `077`). The deadline is durably admitted before automatic send; failed/pre-acceptance state is not recorded as submitted. It refuses symlinks, unsafe existing permissions, invalid state/configuration, and overlapping runs rather than repairing or replacing existing user data. No current host installation, enabled timer, mail submission, or mailbox receipt is implied by these source files.

## Admin metrics and operational alerts

`GET /api/admin/metrics` is protected by the existing authenticated admin-only middleware. It returns database and WAL file sizes, free pages, total snapshots, active credentials, disk free space/usage, quick integrity health, poller running/sweep status, last sweep duration/completion time, and the number of consecutive failed or degraded sweeps. It reports alert codes when filesystem usage reaches 90%, three consecutive sweeps fail/degrade, the poller is stopped, integrity is unhealthy, or a configured recovery-mail socket cannot be reached. A disabled mail bridge is reported as disabled rather than as an outage.

The mail check only connects to the configured Unix socket and closes the connection; it sends no recipient, token, or email and does not invoke sendmail. Alert codes are exposed to an authenticated admin caller; this endpoint does not configure an external notification destination. Public `/health` remains a small readiness/integrity check and does not expose tenant or host storage counts.

## Synthetic concurrent load benchmark

`deploy/bench/synthetic-load-test.ts` sends synthetic GET traffic to `/health`, `/api/data`, `/api/providers/catalog`, `/forgot-password`, and `/privacy`. Defaults are 1,000 requests and 50 concurrent workers; concurrency is bounded to 50–100. The URL is restricted to plain HTTP `127.0.0.1`, redirects are not followed, and configured proxy variables cause the harness to refuse to run. It reports p50/p95/p99 latency, HTTP status/error rate, throughput, and start/peak/end RSS.

Set `USEMETER_BENCH_SESSION_COOKIES` through a secure environment input using only disposable staging sessions, then run:

```sh
bun run deploy/bench/synthetic-load-test.ts
```

The harness requires `USEMETER_BENCH_SESSION_COOKIES` to be a JSON array of 2–100 `usage_session` cookies from distinct **synthetic staging tenants**. It verifies the identities through `/api/auth/me` without printing cookie or identity values; those preflight requests are excluded from the benchmark count. It does not create accounts, call provider adapters, or contact any non-loopback address. Expected error rate is 0%; run it only against a local/staging instance with disposable synthetic accounts, never against production user sessions. The reported RSS window is a measurement, not a leak-proof guarantee.

## Usage snapshot retention (source behavior; not a current-release claim)

A release containing `UsageSnapshotRetention` prunes immediately after the vault and poller initialize, then runs hourly in the background. `SNAPSHOT_RETENTION_DAYS` defaults to `7` and must be a positive safe integer with a safely representable millisecond window; invalid day values are rejected during application startup. The storage method also validates `now` and the computed cutoff as safe integer epoch-millisecond values before reading snapshots. Each run preserves all snapshots with `fetched_at >= now - retentionDays * 86,400,000`, plus each credential's latest snapshot and latest last-good snapshot. Both anchors rank by `fetched_at DESC, id DESC`; a same-time tie therefore selects the larger snapshot ID. Last-good uses the same legacy-compatible health/error classification as the storage reader, including healthy quota-exhausted reports.

At run start, the worker captures a snapshot-ID watermark and computes the protected anchors once. It deletes only older-than-cutoff rows at or below that watermark, in transactions of at most 1,000 deletions, yielding between committed batches. Rows inserted during a run are deferred to a later run even if their provider timestamp is old. Runs do not overlap within the vault. This operation deletes history rows only: it does not delete users, credentials, invitations, secrets, or token metadata.

The checked-in `compose.yaml` forwards the setting as `SNAPSHOT_RETENTION_DAYS: ${SNAPSHOT_RETENTION_DAYS:-7}`. Set a custom value in the Compose interpolation environment (for example, the configured `.env` or `--env-file`); the Compose service must also contain that environment mapping. A `.env` entry by itself does not inject a variable into a container, and older or deployment-specific Compose files need the mapping added explicitly to allow overrides. This source documentation does not establish that the current production image or external production Compose file enables the worker.

Retention does not run a recurring `VACUUM`. SQLite marks deleted pages reusable, so pruning can leave the live database file at its previous size while increasing `freelist_count`; physical compaction is separate offline maintenance. A protected, verified pre-first-start backup of a schema-v2 database retains the prior snapshot rows and encrypted credential metadata as a separate recovery copy. Keep it outside the live volume. Rolling back the image alone cannot restore deleted rows; recovery requires an offline restore from that pre-prune backup under the existing WAL/sidecar safety rules.

**Local synthetic growth measurement (not production or real-user evidence):** On Bun 1.4.2, a seeded 200,000-snapshot / 50-owner / 100-credential database pruned 198,850 rows in 199 batches in 788.42 ms, preserving 150 expired anchors and all 1,000 recent snapshots. Latest-per-owner and last-good query p95 were 2.25 ms and 2.19 ms before pruning, then 0.06 ms each; history p95 was 0.06 ms then 0.04 ms. After a checkpoint, the live synthetic database remained 143,675,392 bytes while free pages rose from 0 to 34,781. A separate synthetic `VACUUM INTO` copy was 876,544 bytes; that is not automatic shrinkage of the live database. The maximum observed timer lag was 219.91 ms, so cooperative yielding is not a strict end-to-end latency bound. These measurements do not establish production performance or deployment status.

## Bounded polling configuration (source, not a live-release claim)

The bounded provider-admission implementation and its environment settings are present in the local source change; they are **not evidence that the currently deployed image has these controls**. The table documents defaults for a release containing that implementation. Do not use it to infer that the running service uses these values until a reviewed release is explicitly deployed and its effective configuration is confirmed.

| Environment variable | Default | Effect |
| --- | ---: | --- |
| `POLL_TIMEOUT_MS` | `30000` | Per-provider-attempt deadline from dispatch, not a sweep/request deadline. |
| `POLL_MAX_CONCURRENT_GLOBAL` | `4` | Maximum active provider attempts per server process, shared by daemon, manual refresh, and staged validation. |
| `POLL_MAX_CONCURRENT_PER_PROVIDER` | `1` | Maximum active attempts per canonical provider ID. |
| `POLL_MIN_PROVIDER_INTERVAL_MS` | `4000` | Minimum spacing between provider attempt dispatch starts; not a limit on every HTTP request inside an adapter. |
| `POLL_MAX_QUEUED_JOBS` | `256` | Maximum jobs waiting in the shared pool. |
| `POLL_ADMISSION_TIMEOUT_MS` | `30000` | Maximum wait for dispatch before local admission rejection; separate from attempt timeout. |

The limits are process-local. Queue-full or admission-timeout responses use HTTP `429`, `Retry-After: 30`, and `errorCode: "POLLER_CAPACITY"`; a staged OAuth attempt that already redeemed a code is terminal and must restart with a fresh session. This local rejection does not represent an upstream provider 429. Provider rate limits, IP challenges, and multi-process coordination have not been established by these settings.

The documented measurements are local synthetic fake-adapter runs, not tests against this VM, the deployed service, real provider APIs, or real users. See the README and specification for the measured scenarios and their limitations. They do not establish production freshness, free-tier safety, or readiness for paid advertising/mass signup. No source/configuration changes, deployment, or live provider calls are part of this documentation update.

## Hosted OAuth completion modes

Claude, Gemini CLI, and Z.ai retain their embedded clients' registered local redirect URIs, but useMeter does not open a callback listener on the remote server. After authorization, paste the final full redirect URL into the provider's manual form. The shared authenticated endpoint is `POST /api/oauth/manual`; session ownership and the stored provider select the exchange, not fields supplied by the browser.

| Flow | Input |
| --- | --- |
| Claude | `http://localhost:54545/callback?code=...&state=...`; `code#state` is also accepted. |
| Gemini CLI | `http://127.0.0.1:8085/oauth2callback?code=...&state=...` |
| Z.ai | `http://127.0.0.1:9999/callback?code=...&state=...` |
| OpenRouter | Automatic same-origin PKCE redirect to `/api/oauth/openrouter/callback`; no code or URL paste. |

For manual URL inputs, the server checks the stored attempt's exact registered URI and state and never fetches the pasted address. Invalid inputs do not consume a valid attempt; valid inputs are claimed before exchange, and cancellation/expiry is checked before credential persistence. This avoids same-port interference between users without changing any upstream redirect whitelist.

OpenRouter uses its [official S256 PKCE callback flow](https://openrouter.ai/docs/guides/overview/auth/oauth): useMeter sends `callback_url` for the same-origin `/api/oauth/openrouter/callback` and a CSPRNG `state`, which OpenRouter returns unchanged after authorization. The server keeps the verifier and binds the callback to the owner’s session; neither the authorization code nor callback URL is pasted. Public callbacks require HTTPS, except for localhost development. When TLS terminates at the reverse proxy, set `TRUST_PROXY=true` only for the controlled proxy path and preserve `Host` and `X-Forwarded-Proto`; the application then derives the HTTPS callback origin from those trusted headers. Without a trustworthy HTTPS origin, initiation fails instead of emitting an internal HTTP callback.

Local tests exercise the hosted flows with synthetic exchanges and validation adapters; that test evidence alone does not verify a live provider account. Separately, one observed OpenRouter OAuth-authorized account returned real USD balance/credit and API-key usage telemetry, supporting `live_verified` for that observed surface only. This does not establish every account, plan, or authorization mode, and inference spendability has not been verified.

## Google OAuth in Docker

Hosted useMeter can authenticate with the embedded desktop-client credentials when no `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` pair is configured. This mode always requests Google's registered loopback URI:

```text
http://127.0.0.1:51121/oauth-callback
```

Google redirects the browser to that address after authorization. In a hosted deployment, the browser's `127.0.0.1` is the user's device, not the useMeter server; a localhost connection failure is expected. Copy the **entire URL** from that tab's address bar and paste it into the manual callback field in useMeter. The dashboard submits `{ sessionId, callbackInput }` to the authenticated `POST /api/oauth/manual` endpoint. The server validates the exact loopback origin/path, state, session owner, and 10-minute expiry, then exchanges the code without fetching the pasted URL. A previously configured public `GOOGLE_OAUTH_REDIRECT_URI` with no client credentials does not block this embedded manual-paste mode in production. The former provider-specific manual endpoint has been removed, not retained as an alias.

For an automatic public HTTPS callback instead, create and manage an OAuth 2.0 Web Client:

1. Open **Google Cloud Console** and navigate to **APIs & Services > Credentials**.
2. Configure the **OAuth consent screen** (external or internal as appropriate).
3. Create credentials: **OAuth client ID** with application type **Web application**.
4. Under **Authorized redirect URIs**, add the exact public callback URL:
   `https://usemeter.example.com/api/oauth/google/callback`
5. Add the resulting client ID, client secret, and redirect URI to your production `.env`:

```env
GOOGLE_OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
GOOGLE_OAUTH_REDIRECT_URI=https://usemeter.example.com/api/oauth/google/callback
```

The public redirect must be HTTPS at exactly `/api/oauth/google/callback` and cannot include a query string, fragment, or user information. Client ID and secret must be supplied together; malformed or mismatched custom configuration fails rather than silently switching clients. The session freezes the selected client and redirect URI for code exchange, and refresh uses the same originating client. Google refresh tokens and OAuth client metadata follow the vault's encrypted-metadata path; Compose enables `CREDENTIAL_METADATA_ENCRYPTION=enabled` by default. The API metadata projection does not expose those client secrets.

Legacy Antigravity credentials that contain a refresh token but no stored OAuth client pair were issued by the embedded desktop client. They continue refreshing with that embedded issuer even if an operator-owned Web client is configured later. New credentials with an explicit stored client pair use that pair; changing environment settings does not reassign a stored refresh token to another client.

> **Provider Compatibility Notice:** Upstream Google quota and usage tracking (e.g. Antigravity / Gemini) behavior depends on provider account/API compatibility and the configured scopes; successful authorization does not guarantee quota data, and tracking remains unverified / experimental.

## Kimi Code quota validation

Kimi Code OAuth authentication succeeding is **not** proof that quota data is recognized. The adapter supports the first-party managed-usage response documented in [MoonshotAI's `managed-usage.ts`](https://github.com/MoonshotAI/kimi-code/blob/main/packages/oauth/src/managed-usage.ts): `usages.limit_5h`, `usages.limit_7d`, and `usages.limit_month_total`, each with a `used_ratio` (and optionally `reset_time`). `usages.limit_month_code` is only a breakdown attached to the monthly total, not a separate quota. A `boosterWallet`-only response does not represent percentage quota.

The first-party parser treats an empty `{}` or `{ usages: {} }` payload as valid managed usage with no quota rows. useMeter preserves that state as a healthy live report with `limits: []`; it does not fabricate a zero-percent balance or turn a connected login into an error. For empty `usages`, useMeter accepts only optional `boosterWallet: null` and known numeric `goods_version` values (`1` or `2`). Error objects, sensitive-only payloads, malformed quota rows, unknown extra fields, and booster-wallet-only responses remain invalid.

`KIMI_CODE_BASE_URL` can override the default Kimi Code API base URL when a deployment needs a different compatible endpoint; normally leave it unset. After deploying this parser update, reauthorize Kimi Code in the **production** dashboard to verify the response available to that account.

> **Account Plan & Region Notice:** An empty response does not establish the user's plan or region. Kimi's [membership documentation](https://www.kimi.com/code/docs/en/kimi-code/membership.html) describes plan-specific coding-quota availability, but useMeter does not infer this account's tier or region from `{}`. No quota is fabricated and no raw payload is displayed or persisted.

### Diagnostic schema clues

For HTTP 200 responses that are neither recognized quota data nor one of the explicit empty forms above, useMeter provides a safe, non-value diagnostic clue without leaking tokens, cookies, email, account identifiers, or numeric quantities:

- `yalnızca hassas anahtarlar içeren nesne`: The server returned a JSON object whose top-level enumerable keys were all recognized as sensitive (such as credentials, tokens, or profile identifiers) and were intentionally excluded from the schema preview.
- `$.key=type; ...`: A sanitized structural type path preview of safe, non-sensitive top-level keys.
- `unsupported schema`: The payload was not a recognized JSON object structure or safe clues could not be extracted.

### Safe staged reauthorization

Reauthorizing Kimi Code in the dashboard uses staged validation: candidate OAuth tokens are validated in memory against `GET /coding/v1/usages` before writing to persistent storage.

- **Failure rollback and preservation:** If an initial authorization or a repeat reauthorization fails upstream (such as HTTP 401/403 unauthorized or an unsupported HTTP 200 payload), zero database mutations occur. For existing accounts, the previously stored valid credentials, refresh token metadata, custom card accents, and historical usage snapshots are preserved intact rather than deleted.
- **Staged server-side validation:** Candidate OAuth tokens are verified server-side against `GET /coding/v1/usages` before writing credentials to the database. Upon successful validation, the credential is persisted and the normalized snapshot is committed and broadcast. Note that client-side polling on completion depends on the deployed frontend bundle (the legacy client bundle may trigger an additional dashboard usage poll until the updated client is loaded).

### Manual token replacement

The manual `POST /api/credentials` path validates the submitted token before replacing the stored credential. A successful replacement keeps the credential ID, card accent, and snapshot history, but replaces account/session metadata with the validated candidate's metadata: it does not inherit the prior account's refresh token, OAuth client, email, account identity, or project. A failed replacement leaves the prior credential unchanged. OAuth completion paths separately preserve same-account metadata when a new refresh token is omitted. Queued polling rereads the owner-bound credential at dispatch so it cannot revive an obsolete authorization after successful replacement.


## Devin on Hosted Deployments

### Default hosted mode: Manual CLI session token
Hosted deployments default to manual credential configuration for Devin. In the dashboard modal, selecting Devin opens the manual credential form with Devin preselected. The form accepts a compatible Devin CLI session token (`devin-session-token$`) only if you already possess one; it does not promise that every account can obtain one.

- **Credential type:** Devin CLI session token (`devin-session-token$`). Devin's [CLI command reference](https://docs.devin.ai/cli/reference/commands) documents `--force-manual-token-flow` as a prompt to paste an existing token; the flag does not export or obtain a token.
- **Credential-file limitation:** Devin's [Enterprise CLI authentication documentation](https://docs.devin.ai/cli/enterprise/devin-auth) gives the `credentials.toml` file location after a successful login for an eligible account, but does not specify a token field or establish compatibility with useMeter's legacy session-token endpoint. Do not assume the file contains a compatible token.
- **API PAT incompatibility:** `cog_` personal access tokens (PATs) are for Devin's V3 REST API and are not accepted by useMeter's legacy Codeium gRPC quota endpoint, which requires the compatible CLI session token.
- **Security note:** Tokens are encrypted in the local SQLite vault with AES-256-GCM. Never share or paste tokens into chat, or store them in unencrypted browser storage. Do not share or paste the whole credentials file.

For UI input help, select Devin's manual credential form and consult the [official Devin CLI documentation](https://docs.devin.ai/cli/troubleshooting).
### Experimental hosted OAuth callback (env-gated)
The server retains support for a public OAuth callback route behind the explicit `DEVIN_OAUTH_REDIRECT_URI` environment variable for future upstream compatibility:

```env
DEVIN_OAUTH_REDIRECT_URI=https://usemeter.example.com/api/oauth/devin/callback
```

When configured, production rejects loopback redirects and requires an absolute HTTPS URL with the exact path `/api/oauth/devin/callback` without query parameters or user info.

> **Experimental / Compatibility Warning:** Upstream support for hosted CLI redirects and any redirect-URI whitelist/registration mechanism remains unconfirmed by Devin. Because Devin CLI authentication typically binds to localhost loopback ports or manual copy-paste tokens, this hosted callback flow is experimental and not guaranteed to function without upstream provider confirmation. Use the manual CLI session token form for reliable hosted usage.

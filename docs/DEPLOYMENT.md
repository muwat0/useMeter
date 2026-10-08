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

### Rollback compatibility rules

**Primary rollback:** stop only `usemeter`, retag the image to point `usemeter:local` back to the exact phase-1 dual-reader image `usemeter:release-4-phase1` (`sha256:177be07af5ccc27610c9a9535bf611b9cf021aabb87902542f71d18b840998ca`), and start only that service with the existing database. The phase-1 reader supports v2 envelopes; the v2 database remains encrypted and must not have encryption disabled. Do not edit `compose.yaml`, change the volume, or restore a database for this application rollback:
```sh
sudo -n /usr/bin/docker image tag usemeter:release-4-phase1 usemeter:local
sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml stop usemeter
sudo -n /usr/bin/docker compose -f /opt/usemeter/compose.yaml up -d --no-build --no-deps --force-recreate usemeter
```

**Exceptional pre-dual-reader recovery:** the older pre-dual-reader image must never be started against a v2 database. Returning to it requires an explicitly approved, fully offline recovery using a verified v1 backup and safe disposition of the active `usage.db`, `usage.db-wal`, and `usage.db-shm` as a complete set. Do not use an ad hoc `cp` restore or leave stale/replayable sidecars beside a restored database. If the complete offline database-and-sidecars recovery cannot be proven safe, remain on the phase-1 dual-reader image with the existing database.

## Operational notes

The deployment is live on `production-server`. Keep the production `.env` file and the named Docker volume outside Git. Do not replace the `my_webapp` application; it is unrelated static/PHP hosting. Updates should be performed by fetching a reviewed release, rebuilding the image, and restarting the Compose service while preserving the named volume.

## Google OAuth in Docker

Hosted useMeter can authenticate with the embedded desktop-client credentials when no `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` pair is configured. This mode always requests Google's registered loopback URI:

```text
http://127.0.0.1:51121/oauth-callback
```

Google redirects the browser to that address after authorization. In a hosted deployment, the browser's `127.0.0.1` is the user's device, not the useMeter server; a localhost connection failure is expected. Copy the **entire URL** from that tab's address bar and paste it into the Google callback field in useMeter. The dashboard submits it to the authenticated `POST /api/oauth/google/manual` endpoint. The server validates the exact loopback origin/path, state, session owner, and 10-minute expiry, then exchanges the code without fetching the pasted URL. A previously configured public `GOOGLE_OAUTH_REDIRECT_URI` with no client credentials does not block this embedded manual-paste mode in production.

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

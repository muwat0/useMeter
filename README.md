# useMeter - Self-hosted AI usage and quota tracking

[![GitHub Release](https://img.shields.io/github/v/release/muwat0/useMeter?color=blue)](https://github.com/muwat0/useMeter/releases)
[![Quality CI](https://github.com/muwat0/useMeter/actions/workflows/quality.yml/badge.svg)](https://github.com/muwat0/useMeter/actions/workflows/quality.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Bun](https://img.shields.io/badge/Runtime-Bun%201.4+-black?logo=bun)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript%20strict-blue?logo=typescript)](https://www.typescriptlang.org)

useMeter brings supported AI provider usage, quota windows, balances, and reset times into one self-hosted dashboard. It stores account data in a local SQLite database and refreshes provider reports in the background.

> **Dashboard preview:** This screenshot uses synthetic demo accounts and usage values; it does not show real credentials or a live account.
> ![useMeter dashboard with synthetic demo data](docs/images/dashboard.png)

## What it does

- Brings provider-reported usage windows, balances, credits, and reset times into one dashboard.
- Keeps a history of usage snapshots and displays stale/error states rather than treating a failed refresh as a current reading.
- Supports multiple accounts and labels, dashboard organization and appearance preferences, and English/Turkish UI text.
- Supports multiple users with separate accounts and usage data; the first account becomes the administrator, who can invite other users.
- Exposes a versioned External API (`/api/v1/summary`, `/api/v1/usage`) with Personal Access Tokens (PAT) for desktop status bars (Waybar, Polybar, tmux) and automation scripts.

Usage is limited to what each provider exposes and what the configured credential can access. Quota values, refresh intervals, available windows, and authorization behavior are provider-dependent; useMeter is not an authoritative billing record.

## Public information pages

The following informational pages are available without signing in:

- `/privacy` — data storage, retention, deletion, and provider requests.
- `/terms` — software-use, billing-data, and credential-responsibility notices.
- `/security` — security controls and responsible vulnerability disclosure.
- `/support` — community support, GitHub issues, and contact details.

Each page supports Turkish and English through `?lang=tr` or `?lang=en`.

## External API & Desktop Widgets

useMeter provides a versioned external HTTP API (`/api/v1/*`) authenticated via Personal Access Tokens (`Authorization: Bearer um_pat_...`) for desktop status bars (Waybar, Polybar, tmux), terminal scripts, and cURL access:

- `GET /api/v1/summary` — compact totals (total prepaid balance, key spending, active accounts, health status) optimized for desktop widgets.
- `GET /api/v1/usage` — normalized, secrets-redacted usage telemetry across all connected accounts.
- `POST /api/v1/poll` — trigger an on-demand provider refresh (rate-limited).

Tokens can be created and managed directly in the dashboard under **Settings (⚙️) → API & External Access**. For complete endpoint specifications, JSON response schemas, and copy-paste integration recipes (Waybar, tmux, CLI scripts), see **[docs/API.md](docs/API.md)**.


## Provider support and verification

The catalog contains the repository's 17 canonical provider adapters. Its tier describes evidence, not an availability promise: `live_verified` means real-provider telemetry has been observed for the listed provider; `connection_verified` means a real connection succeeded but quota telemetry has not been observed; `synthetic_only` means implementation/tests exist without live verification. This does not establish support for every account, plan, region, or authorization path.

| Provider (canonical ID) | Evidence tier | Auth modes | Telemetry kind | Onboarding notes |
| --- | --- | --- | --- | --- |
| OpenRouter (`openrouter`) | `live_verified` | `oauth_callback`, `api_key` | `balance_usd` | Live-verified on one observed OAuth-authorized account for USD balance/credit and API-key usage telemetry; this does not establish every account, plan, or authorization mode. OAuth uses an automatic same-origin S256 PKCE callback; reverse proxies terminating TLS must supply trusted HTTPS origin headers through the existing `TRUST_PROXY` setting. |
| DeepSeek (`deepseek`) | `synthetic_only` | `api_key` | `balance_usd` | DeepSeek Platform API key; returned balance fields depend on the account. |
| Anthropic Claude (`anthropic`) | `synthetic_only` | `oauth_loopback_paste` | `window_percent` | Use a compatible Claude Code OAuth token or paste the callback response. Anthropic API keys are not accepted by the usage endpoint. |
| OpenAI ChatGPT / Codex (`openai-codex`) | `live_verified` | `oauth_device` | `window_percent` | Live verification covers observed Codex usage-window telemetry, not every plan or quota surface. |
| Antigravity (`antigravity`) | `synthetic_only` | `oauth_loopback_paste`, `oauth_callback` | `window_percent` | Hosted setup without operator-owned Google Web OAuth credentials uses the embedded desktop client and requires pasting the full loopback callback URL. An operator-owned Web client with its exact public HTTPS callback enables hosted callback completion. |
| GitHub Copilot (`github-copilot`) | `live_verified` | `oauth_device` | `window_percent` | Live verification covers observed Copilot quota telemetry; plan/seat eligibility remains provider-controlled. |
| Cursor (`cursor`) | `live_verified` | `oauth_device`, `session_cookie` | `window_percent` | Browser OAuth or a compatible Cursor session token/cookie; live verification covers observed usage-window telemetry. |
| xAI Grok (`xai-oauth`) | `live_verified` | `oauth_device` | `window_percent` | Live verification covers observed OAuth usage-percentage telemetry. An xAI API key is not a substitute for the OAuth credential. |
| Zhipu AI / GLM / Z.ai (`zai`) | `synthetic_only` | `oauth_loopback_paste`, `api_key` | `window_percent` | OAuth requires pasting the registered callback URL, or provide a compatible bearer credential. |
| MiniMax Code (`minimax-code`) | `synthetic_only` | `api_key` | `window_percent` | Requires a MiniMax Code token-plan access key; returned windows and resets depend on provider data. |
| Cline Pass (`cline-pass`) | `synthetic_only` | `api_key` | `window_percent` | Reports percentage-based usage windows, not a monetary balance or token-credit balance. |
| Devin (`devin`) | `synthetic_only` | `oauth_callback`, `session_cookie` | `token_credits` | Only a compatible existing Devin CLI session token is supported; `cog_` V3 PATs are unsupported. Hosted OAuth redirect compatibility is experimental and unverified. |
| Umans (`umans`) | `synthetic_only` | `api_key` | `token_credits` | Reports provider request counters and available plan data, not a USD balance. |
| Google Gemini CLI (`google-gemini-cli`) | `synthetic_only` | `oauth_loopback_paste` | `window_percent` | Separate from Antigravity; OAuth completion requires pasting the registered loopback callback URL. |
| Kimi Code (`kimi-code`) | `connection_verified` | `oauth_device` | `window_percent` | Account connected; provider reports no quota data. This neutral result does not establish membership, plan, or region; standard API keys are not accepted. |
| OpenCode Go (`opencode-go`) | `synthetic_only` | `api_key` | `window_percent` | Requires an API key for an active OpenCode Go subscription. |
| Alibaba Qwen (`alibaba-token-plan`) | `synthetic_only` | `api_key`, `session_cookie` | `window_percent` | Requires a supported token-plan API key and console session cookie; OAuth credentials are not supported. |

`window_percent` describes percentage-based quota windows; `balance_usd` describes monetary balance; `token_credits` groups provider-reported token, credit, or request counters. The canonical, bilingual matrix is also exposed without authentication at `GET /api/providers/catalog`; it contains provider metadata only and no credentials or secrets. The client displays the evidence tier and telemetry kind before connection.

Provider values and behavior can change upstream. A successful OAuth exchange alone does not guarantee that a provider returns quota data. The Kimi neutral no-quota state is not evidence that an account lacks a paid plan or uses the wrong region.

## Run locally

### Prerequisites

- [Bun](https://bun.sh/) and Git.
- OpenSSL for generating a random master key. The container image is based on Bun 1.4.0; that image pin is not a statement of the minimum supported Bun version.

### Install, build, and start

Build the browser client before starting the server: the server serves the generated files from `dist/client/`.

```sh
git clone https://github.com/muwat0/useMeter.git
cd useMeter
bun install
bun run build

# Run key setup, loading, validation, and startup in a subshell so any failure
# stops this snippet without leaving shell state behind.
(
  set -eu
  key_file="$HOME/.config/usemeter/local.env"
  install -d -m 700 "$HOME/.config/usemeter"
  if [ ! -e "$key_file" ]; then
    key=$(openssl rand -hex 32)
    [ -n "$key" ]
    (umask 077; set -C; printf 'export USAGE_MASTER_KEY=%s\n' "$key" > "$key_file")
  fi
  unset USAGE_MASTER_KEY
  . "$key_file"
  [ -n "${USAGE_MASTER_KEY:-}" ] || { printf 'USAGE_MASTER_KEY is missing or empty\n' >&2; exit 1; }
  export USAGE_MASTER_KEY
  bun run start
)
```

Generating or overwriting the master key after saving credentials makes existing stored secrets unreadable. Always reuse the same key for later runs and keep it backed up securely. The server uses `data/usage.db` by default and listens on port `3100` unless configured otherwise.

Open <http://localhost:3100/register> to create the first account; it is automatically assigned the administrator role. Public registration remains enabled by default. Sign in at <http://localhost:3100/login>, then use the Admin controls to disable public registration before exposing the service to other users. Use a password of at least 12 characters. Sign in at <http://localhost:3100/login> on subsequent visits.

## Docker Compose

Compose builds the client into the image, runs the service as a non-root user, and stores SQLite data in the named `usemeter-data` volume at `/app/data/usage.db`.

Generate a persistent key file outside the checkout on initial setup (an existing file is reused), then start the service:

```sh
(
  set -eu
  env_file="$HOME/.config/usemeter/compose.env"
  install -d -m 700 "$HOME/.config/usemeter"
  if [ ! -e "$env_file" ]; then
    key=$(openssl rand -hex 32)
    [ -n "$key" ]
    (umask 077; set -C; printf 'USAGE_MASTER_KEY=%s\n' "$key" > "$env_file")
  fi
  [ -s "$env_file" ] || { printf 'Compose key file is missing or empty: %s\n' "$env_file" >&2; exit 1; }
  unset USAGE_MASTER_KEY
  docker compose --env-file "$env_file" up -d --build
)
```

Compose normally gives an inherited shell variable precedence over the value in `--env-file`. The startup subshell above clears `USAGE_MASTER_KEY` before invoking Compose so the persisted key file supplies the value. Every later Compose command must use the same file, confirm it is nonempty, and clear any inherited variable in a subshell; for example:

```sh
(
  set -eu
  env_file="$HOME/.config/usemeter/compose.env"
  [ -s "$env_file" ] || { printf 'Compose key file is missing or empty: %s\n' "$env_file" >&2; exit 1; }
  unset USAGE_MASTER_KEY
  docker compose --env-file "$env_file" up -d
)
```

Do not regenerate or overwrite this key: doing so makes stored credentials unreadable.

The default host binding is `127.0.0.1:3100`; this keeps the port off public interfaces and is suitable when a local reverse proxy forwards to it. The host port and bind address can be changed with `USEMETER_PORT` and `USEMETER_BIND_ADDRESS`; do not bind publicly unless you intentionally provide TLS, network access controls, and a trusted deployment perimeter. Preserve the named volume when recreating containers. `docker compose down -v` removes the volume and its database.

For a public deployment, terminate HTTPS at a trusted reverse proxy and keep the application port private. Set `TRUST_PROXY=true` only when the service can only be reached through that trusted proxy and forwarded headers cannot be forged by direct clients. See the [Docker deployment guide](docs/DEPLOYMENT.md) for proxy and data-migration details.

## Configuration and security

| Variable | Purpose and default |
| --- | --- |
| `USAGE_MASTER_KEY` | Required in production; do not use the development fallback. Derives the encryption key for stored credential secrets. Use a long random value, keep it stable, and keep backups protected. |
| `NODE_ENV` | Runtime mode. Compose sets `production`; production mode rejects a missing or development-default master key. |
| `PORT` | HTTP listener port; defaults to `3100`. Compose uses container port `3100`. |
| `DATABASE_PATH` | SQLite database path; defaults to `data/usage.db` locally and `/app/data/usage.db` in Compose. Persist the containing directory/volume. |
| `POLL_TIMEOUT_MS` | Optional per-provider-attempt deadline; defaults to `30000` ms. Must be a finite positive integer no greater than `2147483647`. Applies to background/manual polling and staged credential validation, including manual and OAuth/device submissions; it is not a whole-sweep or full HTTP-request timeout. |
| `POLL_MAX_CONCURRENT_GLOBAL` | Maximum provider attempts dispatched at once across all polling callers; defaults to `4` per server process. Positive safe integer. |
| `POLL_MAX_CONCURRENT_PER_PROVIDER` | Maximum concurrent dispatched attempts for one canonical provider ID; defaults to `1`. Positive safe integer. |
| `POLL_MIN_PROVIDER_INTERVAL_MS` | Minimum spacing between dispatch starts for a canonical provider ID; defaults to `4000` ms. Integer from `0` through `2147483647`. This limits poll-attempt starts, not every HTTP call an adapter may make. |
| `POLL_MAX_QUEUED_JOBS` | Maximum waiting jobs in the shared provider queue; defaults to `256`. Positive safe integer. |
| `POLL_ADMISSION_TIMEOUT_MS` | Maximum time a job may wait for provider dispatch; defaults to `30000` ms. Integer from `1` through `2147483647`. This is separate from `POLL_TIMEOUT_MS`, which begins at dispatch. |
| `USEMETER_BIND_ADDRESS` | Compose host-side bind address; defaults to `127.0.0.1`. This controls the published host port, not the container listener. |
| `USEMETER_PORT` | Compose host-side port; defaults to `3100`. |
| `TRUST_PROXY` | Defaults to `false`. Enable only behind a trusted proxy that protects forwarded headers. |
| `CORS_ALLOWED_ORIGINS` | Optional comma-separated origins permitted for cross-origin mutation requests; empty by default. |
| `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_REDIRECT_URI` | Optional Google OAuth configuration. With no client credentials, hosted production uses the embedded desktop client and manual loopback callback paste; a public redirect URI by itself does not block this fallback. To use automatic public callbacks, configure an operator-owned Google Cloud OAuth Web client and its exact `https://<your-domain>/api/oauth/google/callback` URI. A client ID and secret must be configured together. |
| `DEVIN_OAUTH_REDIRECT_URI` | Optional Devin OAuth redirect configuration; hosted redirect compatibility remains experimental. |
| `ZAI_OAUTH_CLIENT_ID`, `ZAI_OAUTH_CLIENT_SECRET` | Optional Zhipu AI OAuth client configuration. |
| `KIMI_CODE_BASE_URL` | Optional Kimi Code usage API base URL override; the adapter otherwise uses its built-in provider endpoint. |
| `CREDENTIAL_METADATA_ENCRYPTION` | Compose enables metadata-envelope encryption by default. Once a database has migrated to schema version 2, disabling it is not a supported downgrade; read the deployment guide before changing this setting or migrating an existing database. |

Each daemon/manual credential poll and staged credential validation uses a deadline-bound attempt signal, composed with caller cancellation when supplied. On deadline or caller cancellation, the poller aborts it and ends its wait; an adapter that ignores abort may continue upstream work, but late results and token callbacks cannot write. Optional provider lookups remain best-effort for ordinary failures, while abort is not swallowed and retry waits are abortable. Normal-poll expiry follows existing stale/error behavior: keep last-good limits in a stale report or return empty limits for a first failure. Staged-validation expiry/cancellation fails without saving the candidate credential or usage snapshot; failed reauthorization leaves the existing credential, metadata, accent, and usage history unchanged. Before writes, the poller enforces the monotonic deadline and, when supplied, the store-backed `beforeCommit` check. Commit admission is the synchronous point of no return: an admitted commit that completes returns success even if synchronous SQL work crosses the deadline, while storage exceptions still propagate. JavaScript timers cannot preempt synchronous CPU/SQL work, so a successful commit not admitted before expiry is rejected.

Daemon polling, manual refresh, and staged credential validation share one per-process provider admission pool. A job waiting for a provider slot or its minimum dispatch interval does not occupy an active slot; eligible providers can dispatch while another provider is cooling down. Same credential jobs coalesce only within the same owner scope. A queued credential is reread from the vault before dispatch, so reauthorization is observed and deleted credentials are skipped; already-dispatched work cannot overwrite a newer credential epoch. Caller cancellation removes queued work immediately. A full queue or a job that cannot be admitted before its admission deadline returns HTTP `429` with `Retry-After: 30` and `errorCode: "POLLER_CAPACITY"`; local admission rejection does not create a provider-failure snapshot or replace candidate credentials. Expired/cancelled/foreign OAuth sessions retain their existing precedence. Staged OAuth validation that already redeemed a code becomes terminal and requires a new flow after capacity rejection; ordinary provider `429` without the local-capacity flag remains a provider result and does not itself require a new OAuth session.

The defaults are conservative process-local controls, not a provider quota guarantee or a multi-instance coordination mechanism. The daemon's nominal interval remains five minutes, but an overlong sweep can overlap a later tick; measurements below do not establish a five-minute freshness guarantee under faults.

**Local synthetic load observation (not production/provider testing):** A local process with 500 synthetic credentials (250 owners, two each, eight fake provider fixtures), an 80 ms fake provider delay, and a 4000 ms minimum provider dispatch gap completed a healthy sweep in 248.228 s: 500 calls, peak 4 global / 1 per provider, measured minimum start gap 4000.0276 ms, 500 healthy reports, zero stale/errors, maximum last-good age 248.145 s, RSS 66 MiB, CPU 1047 ms user / 422 ms system. In a separate run where every 50th fake request hung until its 30 s attempt deadline, completion took 326.232 s: 500 calls, peak 4 / 1, minimum gap 4000.3558 ms, 490 healthy and 10 stale, zero first-time errors, all 50 seeded stale quota states preserved, maximum last-good age 386.290 s, RSS 68 MiB, CPU 1637 ms user / 704 ms system. These are local fake-adapter observations, not real VM, real-user, provider-limit, upstream retry, free-tier, or ad-readiness evidence. A provider adapter may make multiple upstream requests during one spaced poll attempt, and slow fault cycles can leave an older sweep running when the next nominal tick arrives.

Headless Chromium was also exercised against a local fake OAuth endpoint: capacity terminal failures displayed a restart action and started a new session rather than polling the old session again, while an ordinary injected upstream `429` retried the same session; a delayed invalid-manual-token response did not overwrite a newly started form. This was synthetic UI behavior verification, not a real-provider authorization test.

For retrying a local capacity rejection, wait at least the returned `Retry-After` before trying again. Staged OAuth/device flows that report `restartRequired: true` must restart with a new session; do not reuse a redeemed authorization code. A regular provider-side HTTP `429` is distinct and follows provider retry/stale behavior.

The encryption key derivation retains only the current effective master-secret-derived key in private module state; each encrypt/decrypt still runs the production key guard, and changing the trimmed effective secret causes a fresh derivation. This avoids repeating synchronous scrypt for every operation without changing the ciphertext format, key exposure, or key-rotation behavior.


Credential secrets are encrypted at rest using AES-256-GCM with a key derived from `USAGE_MASTER_KEY`; passwords use Argon2id, and session tokens are stored as hashes. Metadata encryption has a separate versioned migration setting, so do not interpret the secret-encryption statement as a blanket guarantee that every historical database field or backup is encrypted. Keep database files, backups, the master key, and environment files protected. Do not commit credentials, OAuth client secrets, or populated `.env` files.

## Development commands

| Command | Purpose |
| --- | --- |
| `bun install` | Install dependencies from the lockfile. |
| `bun run build` | Build the browser client into `dist/client/`. |
| `bun run start` | Start the service with `src/index.ts`. |
| `bun run dev` | Start the server in Bun watch mode. |
| `bun run dev:client` | Rebuild the client when frontend files change. |
| `bun x tsc --noEmit` | Check TypeScript types across client and server. |
| `bun test` | Run the test suite. |
| `(unset USAGE_MASTER_KEY && docker compose --env-file "$HOME/.config/usemeter/compose.env" up -d --build)` | Build and start the Compose service. |
| `(unset USAGE_MASTER_KEY && docker compose --env-file "$HOME/.config/usemeter/compose.env" logs -f usemeter)` | Follow service logs. |
| `(unset USAGE_MASTER_KEY && docker compose --env-file "$HOME/.config/usemeter/compose.env" down)` | Stop and remove the Compose service/container without deleting the named data volume. |

CI uses Bun 1.4.0, matching the container runtime. Validate networking regressions on that pinned version as well as your local runtime. HTTP-disconnect tests close the actual request/socket and wait for server and upstream abort events; a rejected `fetch` promise alone does not prove that the connection closed.

The health endpoint is `/health`. The application is a Bun server and must run as a service; it cannot be deployed as static files alone.

## Further reading

- [Technical specification](docs/SPEC.md)
- [Docker deployment guide](docs/DEPLOYMENT.md)
- [ADR-0001: Self-hosted BFF architecture](docs/adr/0001-self-hosted-bff-architecture.md)
- [ADR-0002: Dual-engine tracking model](docs/adr/0002-dual-engine-tracking-model.md)
- [ADR-0003: Multi-tenant session authentication](docs/adr/0003-multi-tenant-session-authentication.md)
- [ADR-0004: Security perimeter and invitation onboarding](docs/adr/0004-security-perimeter-and-invitation-onboarding.md)
- [ADR-0005: Non-destructive stale usage state](docs/adr/0005-nondestructive-stale-usage-state.md)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on development setup, adding new provider adapters, and submitting pull requests.

## License

useMeter is open source software licensed under the [MIT License](LICENSE).

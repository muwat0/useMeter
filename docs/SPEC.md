# SPEC.md — useMeter: AI Quota, Balance, and Usage Tracking System Technical Specification

- **Version:** 1.0.0
- **Date:** 2026-09-13
- **References:** [CONTEXT.md](../CONTEXT.md), [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md), [ADR-0003](adr/0003-multi-tenant-session-authentication.md), [ADR-0004](adr/0004-security-perimeter-and-invitation-onboarding.md), [ADR-0005](adr/0005-nondestructive-stale-usage-state.md)
- **Accepted ADRs:** [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md), [ADR-0003](adr/0003-multi-tenant-session-authentication.md), [ADR-0004](adr/0004-security-perimeter-and-invitation-onboarding.md), [ADR-0005](adr/0005-nondestructive-stale-usage-state.md)
---

## 1. System Overview

The system tracks real-time balances, quota windows, and reset times for multiple AI providers. The repository contains **17 canonical provider adapters**; their real-world evidence levels are distinct.

The system has evolved from a local desktop dashboard for a single user to operating with user-based authentication, row-level tenant isolation (`ownerId`), session security, and authorized API access.

### 1.1 Provider Support, Evidence Level, and Telemetry Type

`live_verified` means valid telemetry was observed from a real provider; `connection_verified` means a real account connection succeeded but quota telemetry was not observed; `synthetic_only` means only adapter/synthetic behavior is available. None guarantees support for every plan, region, or authorization path.

| Provider (canonical ID) | Evidence level | Authentication modes | Telemetry type |
| --- | --- | --- | --- |
| OpenRouter (`openrouter`) | `synthetic_only` | `oauth_callback`, `api_key` | `balance_usd` |
| DeepSeek (`deepseek`) | `synthetic_only` | `api_key` | `balance_usd` |
| Anthropic Claude (`anthropic`) | `synthetic_only` | `oauth_loopback_paste` | `window_percent` |
| OpenAI ChatGPT / Codex (`openai-codex`) | `live_verified` | `oauth_device` | `window_percent` |
| Antigravity (`antigravity`) | `synthetic_only` | `oauth_loopback_paste`, `oauth_callback` | `window_percent` |
| GitHub Copilot (`github-copilot`) | `live_verified` | `oauth_device` | `window_percent` |
| Cursor (`cursor`) | `live_verified` | `oauth_device`, `session_cookie` | `window_percent` |
| xAI Grok (`xai-oauth`) | `live_verified` | `oauth_device` | `window_percent` |
| Zhipu AI / GLM / Z.ai (`zai`) | `synthetic_only` | `oauth_loopback_paste`, `api_key` | `window_percent` |
| MiniMax Code (`minimax-code`) | `synthetic_only` | `api_key` | `window_percent` |
| Cline Pass (`cline-pass`) | `synthetic_only` | `api_key` | `window_percent` |
| Devin (`devin`) | `synthetic_only` | `oauth_callback`, `session_cookie` | `token_credits` |
| Umans (`umans`) | `synthetic_only` | `api_key` | `token_credits` |
| Google Gemini CLI (`google-gemini-cli`) | `synthetic_only` | `oauth_loopback_paste` | `window_percent` |
| Kimi Code (`kimi-code`) | `connection_verified` | `oauth_device` | `window_percent` |
| OpenCode Go (`opencode-go`) | `synthetic_only` | `api_key` | `window_percent` |
| Alibaba Qwen (`alibaba-token-plan`) | `synthetic_only` | `api_key`, `session_cookie` | `window_percent` |

`window_percent` denotes percentage-based quota windows, `balance_usd` denotes monetary balance, and `token_credits` denotes provider-reported token/credit/request counters. Kimi's known neutral result is **“Account connected; provider does not report quota”**; this is not an inference about a paid plan or region. Devin does not support `cog_` V3 PATs, and hosted OAuth redirection is experimental/unverified. Antigravity's embedded desktop OAuth client requires manually pasting the full loopback callback URL; an automatic hosted callback requires the operator's own Google OAuth Web client and matching HTTPS URI.

The canonical catalog can be read without authentication through `GET /api/providers/catalog`; the response contains provider metadata only, not secrets or tokens. Before connecting, the client displays the evidence level and telemetry type.

---

## 2. Authentication and Account Lifecycle

### Identity and Password

- Email is canonicalized with `trim().toLowerCase()` and stored in `users.email` with `COLLATE NOCASE` uniqueness.
- For new passwords, the same validator requires at least 12 Unicode characters **and** at least 12 JavaScript code units, and at most 256 Unicode characters, 256 code units, and 256 UTF-8 bytes.
- Passwords are hashed with Bun `Bun.password` Argon2id (`memoryCost: 65536`, `timeCost: 2`). Login returns the same generic authentication error for an invalid email/password and an unknown user.

### Server Sessions and Cookie

- Sessions are stateful SQLite records; no JWT is issued to the client. A session token is an opaque string generated from 32 random bytes; only its SHA-256 `token_hash` is stored in the vault.
- The cookie is named `usage_session`; it uses `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` in production/HTTPS environments. A session is valid for 30 days (`2,592,000` seconds).
- `logout` deletes only that token. A password-change operation preserves the active session that performed it and atomically deletes the user's other sessions. A successful password reset deletes all of the user's sessions and does not sign them in automatically.

### Password Change, Recovery, and Account Deletion

The vault rechecks the validation binding immediately before the irreversible SQL write. Password changes require an active user session and the current password; the new password must pass the common password rule. If the password or session changes/is revoked during hashing, the stale request cannot write. A successful change invalidates all reset records and cancels the user's pending provider authorization attempts/provider jobs.

Before checking whether the user exists on the server, password recovery places every valid email request in the same bounded queue. No email is sent for an unknown address. The request returns the same `202 {success:true}` response for known/unknown users and background delivery errors. If mail is not configured or the queue is full, all accounts receive `503 RECOVERY_UNAVAILABLE`; when the request/recovery rate limit is exceeded, the response is `429 RATE_LIMITED` with `Retry-After`. A recovery request does not perform expensive password hashing.

Only the newest reset token for each user is valid; the token is 32 random bytes, only its SHA-256 digest is stored in the database, it expires after 15 minutes, and it is single-use. A new request invalidates the previous token. Successful consumption revalidates the token digest, expiration time, and password hash from token issuance within a transaction; the password change and invalidation of all user sessions and reset tokens occur in the same transaction. A token that is still valid may be confirmed even if the mail service is subsequently unconfigured. The reset link uses the required canonical HTTPS origin and the format `/reset-password#token=...`; the token is not placed in a query string or server API response.

The reset token's owner identifies the target user; if the request also supplies a session cookie belonging to another user, only the token owner's password/sessions are changed, and the cookie or data is unaffected. The API response does not reveal the token owner's identity.

Self-deletion requires a valid active session and the current password. Deletion is rejected by a guard within the transaction if the user is the last administrator. Successful deletion removes the user row; SQLite FK cascade deletes sessions, credentials, usage snapshots, reset tokens, and invitations created by that user. Pending OAuth/poller jobs are cancelled; other owners' data is unchanged. The admin deletion endpoint performs the same target-owner job cleanup, but an administrator cannot delete their own account through the admin endpoint.

### Service and Mail Boundaries

- `AuthService` provides password change, reset request/confirmation, account deletion, and `stopPasswordRecovery()`. The application sends recovery mail only through the injected Unix-socket mailer when `RECOVERY_MAIL_SOCKET` is non-empty; an empty value disables recovery requests and does not use fake/log-only delivery.
- The queue allows at most 2 active jobs and 32 pending jobs at a time. Pending jobs are dropped after 30 seconds; mail sending is aborted after 5 seconds; there is no automatic retry. These values are code constants, not configuration keys.
- The mail bridge accepts only a recipient email address and a 64-character lowercase hexadecimal token. The canonical public origin and sender are configured on the host; the bridge puts the token in a `/reset-password#token=...` link, and the host invokes `/usr/sbin/sendmail` without a shell. A local synthetic sendmail smoke test does not prove real mail delivery or DKIM.

### HTTP API (Account Lifecycle)

| Endpoint | Request | Success | Main errors |
| --- | --- | --- | --- |
| `POST /api/auth/password/change` | `{currentPassword,newPassword}` | `200 {success:true}`; same session is preserved | incorrect current password `401 INVALID_CREDENTIALS`; weak password/input `400 WEAK_PASSWORD`; unauthorized session `401 UNAUTHENTICATED`; rate limit `429 RATE_LIMITED` |
| `POST /api/auth/password/reset-request` | `{email}` | `202 {success:true}` with configured mailer | invalid email `400 INVALID_EMAIL`; unconfigured/full queue `503 RECOVERY_UNAVAILABLE`; rate limit `429 RATE_LIMITED` |
| `POST /api/auth/password/reset-confirm` | `{token,newPassword}` | `200 {success:true}`; no new cookie is issued | invalid/used/expired token `400 INVALID_RESET_TOKEN`; weak password `400 WEAK_PASSWORD`; rate limit `429 RATE_LIMITED` |
| `DELETE /api/auth/account` | `{password}` | `200 {success:true}` and the current cookie is expired | incorrect password `401 INVALID_CREDENTIALS`; invalid session `401 UNAUTHENTICATED`; last admin `409 LAST_ADMIN`; rate limit `429 RATE_LIMITED` |

The new public pages are `GET /forgot-password` and `GET /reset-password`. The reset token is loaded from the URL fragment and the page history is cleared immediately; the reset page has no external scripts, stylesheets, fonts, or images and applies `Referrer-Policy: no-referrer`. API mutations undergo same-origin checks. Unsuccessful account lifecycle responses have the form `{success:false,error,errorCode}`; the client localizes them using `errorCode`.

### Public Information Pages

The login-free `/privacy`, `/terms`, `/security`, and `/support` pages provide privacy, terms of use, security disclosure, and support information. Pages share the dashboard's stored language and theme preferences; an explicit `?lang=tr` or `?lang=en` takes precedence. The theme control always describes the next action: light mode offers “Dark theme” and dark mode offers “Light theme”, with equivalent Turkish labels. Its icon, tooltip, and accessible label update together after a toggle and when restoring the saved theme on page load. These pages load no external resources and allow only their fixed preference script's SHA-256 hash in the script CSP, with inline styles and `no-referrer`.



### Local Account-Lifecycle UI Surface Verification (Not Proof of Live Delivery)

The account lifecycle was tested with an in-memory SQLite `StorageVault`, real `AuthService`/Hono routes, and a compiled React surface at headless viewports of 1280×913 and 720×965. The mail sender and provider adapter were synthetic; no requests were sent to an external provider, network mail server, or real user.

- EN/TR password change, incorrect current password, mismatched password, valid change, preservation of the current session, and cancellation of other sessions worked.
- EN/TR reset requests returned the same generic response for known/unknown accounts. After the token was read from the fragment, the address-bar history was cleared; the token was not exposed in the DOM, browser storage, or `window`. Reset cancelled all old sessions, did not sign in automatically, and rejected replay and a reloaded used link.
- Closing and reopening the Settings panel reset the password fields and deletion confirmation; deletion could not be initiated without confirmation. A last-admin deletion attempt was rejected and the admin session was preserved.
- After a regular user's confirmed self-deletion, their own session returned `401` and their credentials/history were cleared; another owner's credentials, history, and session remained unchanged.
- The reset page loaded no external resources; no browser console error was observed.

This headless evidence does not verify delivery to a real mailbox, MTA acceptance, DKIM signing, production host socket permissions, or a live deployment.

## 3. Module Architecture and Seams (Deep Modules & Seams)

The system is designed according to John Ousterhout's *"Deep Module"* philosophy. Each module hides complex logic (encryption, network backoffs, data transformations) behind a small, simple public interface.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          APPLICATION CORE                            │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ 1. Storage Vault  │ 2. Poller Daemon  │ 3. Ingress Proxy               │
│ (Encrypted SQLite)│ (Jitter + Lock)   │ (Header Capture)               │
├───────────────────┴───────────────────┴────────────────────────────────┤
│                     4. Provider Adapters Seam                          │
│                     fetchUsage(credential) -> Report                   │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ • 17 canonical providers; see evidence matrix in §1.1                     │
├───────────────────┴───────────────────┴────────────────────────────────┤
│ 5. Notification Engine (Telegram / ntfy / Discord)                     │
├────────────────────────────────────────────────────────────────────────┤
│ 6. HTTP API & SSE Gateway (Hono) -> React Dashboard UI                │
└────────────────────────────────────────────────────────────────────────┘
```

### Module 1: Provider Adapter Seam (`src/core/providers/`)
All providers connect to the system through a single seam interface:

```typescript
export type UsageUnit = "percent" | "tokens" | "requests" | "credits" | "usd";
export type UsageStatus = "ok" | "warning" | "exhausted" | "unknown";

export interface UsageLimit {
  id: string;               // e.g.: "5h", "weekly_sonnet", "balance_usd"
  label: string;            // e.g.: "5-Hour Rolling Window"
  amount: {
    used?: number;
    limit?: number;
    remaining?: number;
    usedFraction?: number;  // 0.0 - 1.0 (1.0 = exhausted)
    unit: UsageUnit;
  };
  window?: {
    id: string;             // "5h", "7d", "monthly"
    durationMs?: number;
    resetsAt?: number;      // Epoch ms
    resetLabel?: string;    // "resets" / "regen"
  };
  status: UsageStatus;
  notes?: string[];
}

export type UsageReportHealth = "healthy" | "stale" | "error";
export type UsageReportSource = "live" | "stale" | "error";

export interface UsageReport {
  ownerId?: string;
  provider: string;
  credentialId?: string;
  accountId?: string;
  accountLabel?: string;
  fetchedAt: number;
  limits: UsageLimit[];
  error?: string;
  raw?: unknown;
  health?: UsageReportHealth;
  stale?: boolean;
  lastGoodFetchedAt?: number;
  source?: UsageReportSource;
}

export interface ProviderAdapter {
  id: string;
  supports(provider: string): boolean;
  fetchUsage(credential: StoredCredential, context: FetchContext): Promise<UsageReport>;
  parseHeaders?(headers: Headers, now?: number): UsageReport | null;
}
```

- **Depth:** The caller does not know whether a provider uses OAuth, a token, or custom internal JSON; it only calls `fetchUsage(cred)` and receives a normalized `UsageReport`.

---

### Module 2: Secure Vault and Data Layer (`src/core/storage/`)
It runs on a SQLite database (in WAL mode). Foreign keys (`PRAGMA foreign_keys = ON;`) and indexes are enabled.
Sensitive provider fields (API keys, OAuth refresh tokens) are encrypted with **AES-256-GCM**.

User identity and usage-data queries are scoped by `ownerId`. The daemon can read all credential references only through explicitly internal (`Internal`) vault methods. `StorageVault` is a synchronous module running on Bun SQLite; its core interfaces, which take an owner, are:

```typescript
saveCredential(ownerId: string, input: InputCredential): StoredCredential
listCredentials(ownerId: string, provider?: string): StoredCredential[]
getCredential(ownerId: string, id: string): StoredCredential | null
deleteCredential(ownerId: string, id: string): boolean
saveUsageSnapshot(ownerId: string, report: UsageReport): boolean
getLatestUsage(ownerId: string): UsageReport[]
```

When a user's credential is deleted, its usage snapshots are deleted by SQLite `ON DELETE CASCADE`. User self-deletion likewise cascades to sessions, credentials, usage records, reset tokens, and invitations created by that user, all linked to the user by foreign keys.


#### Database Schema (SQLite)

```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    account_label TEXT NOT NULL,
    accent TEXT NOT NULL DEFAULT 'default',
    credential_type TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    metadata TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_owner_id ON credentials(owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_owner_prov_label
    ON credentials(owner_id, provider, account_label);

CREATE TABLE IF NOT EXISTS usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    account_label TEXT NOT NULL,
    report_json TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_cred_time
    ON usage_snapshots(credential_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_owner_time
    ON usage_snapshots(owner_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_owner_cred_time
    ON usage_snapshots(owner_id, credential_id, fetched_at DESC);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    accepted_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON invitations(created_by);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    password_hash_at_issue TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
```

`password_reset_tokens` enforces the latest-token rule with one row per user. The plaintext reset token is not stored; the record is subject to user-deletion cascade and atomic invalidation on password change/reset consumption. Adding this table does not change the credential metadata `PRAGMA user_version`.

#### Atomic Claim of Legacy Data (First-User Legacy Claim)
All records from the single-user version whose `owner_id` is `NULL` are atomically claimed by the first actual user to register (the first record in the `users` table) within a single SQLite transaction:
```sql
-- Run automatically when the first user registers:
UPDATE credentials SET owner_id = :firstUserId WHERE owner_id IS NULL;
UPDATE usage_snapshots SET owner_id = :firstUserId WHERE owner_id IS NULL;
```
No orphaned records remain after this operation or for users who register later; other users see only the credentials and quotas they add themselves.

#### UsageHistoryRetention: Usage History Retention Policy

The default retention period for `usage_snapshots` history is **7 days**. `SNAPSHOT_RETENTION_DAYS` changes this period using a positive safe integer. Records outside the retention window are evaluated during the first cleanup at application startup and then by a background job that runs hourly.

The window end is calculated as `cutoff = now - retentionDays * 86_400_000`; all snapshots with `fetched_at >= cutoff` are retained. Before touching the database, the storage operation validates that `now`, the retention window, and the calculated `cutoff` are within the epoch-millisecond safe integer range. In addition, at most two `ProtectedUsageSnapshot` anchors are retained per credential:

- **Newest record:** the first record in `fetched_at DESC, id DESC` order, regardless of success/health status.
- **Most recent successful record:** the first successful record according to the same classification as the `StorageVault` last-good reader. A truthy `error`, `health`/`source` values of `error` or `stale`, or only the boolean `stale: true` makes a record unsuccessful. Missing fields in old reports and an `error` field of `null`, `false`, `0`, or an empty string are compatible with success; a healthy quota-exhausted report also counts as successful.
- Old reports containing malformed JSON or JSON `null` do not count as the last-successful snapshot; a malformed report may still be retained as the credential's newest-any anchor.

If both anchors point to the same row, it is retained only once. For equal `fetched_at` values, the larger snapshot ID wins; a later-inserted row with an older `fetched_at` does not displace the newest/most-recent-successful selection. These rules are applied separately for each user and credential.

Each run obtains a single `MAX(id)` watermark at startup and calculates the anchor set once, up to that watermark. Only `usage_snapshots` rows with `id <= watermark`, `fetched_at < cutoff`, and not in the anchor set may be deleted. Rows added while a run is in progress are left for the next run, even if their `fetched_at` is old. Deletion occurs in committed transactions of at most 1,000 rows, yielding to the event loop between transactions. This cleanup does not delete users, credentials, invitations, identity credentials, or token metadata.

Routine retention does not run `VACUUM`. SQLite may reuse deleted pages within the database; therefore, the active DB file does not necessarily shrink on its own.

### Module 3: Active Poller Daemon (`src/core/poller/`)
This is a scheduler that runs periodically in the background.

```typescript
export interface PollerOptions {
  intervalMs?: number;       // Default: 300_000 ms
  pollTimeoutMs?: number;    // Default: 30_000 ms, per attempt
  maxConcurrentGlobal?: number;       // Default: 4 / process
  maxConcurrentPerProvider?: number;  // Default: 1
  minProviderIntervalMs?: number;     // Default: 4_000 ms
  maxQueuedJobs?: number;             // Default: 256
  admissionTimeoutMs?: number;        // Default: 30_000 ms
}

export interface PollerEngine {
  start(): void;
  stop(): void;
  pollAllInternal(): Promise<UsageReport[]>;
  pollOwner(ownerId: string, credentialId?: string): Promise<UsageReport[]>;
  onReport(callback: (report: UsageReport, ownerId?: string) => void): void;
}
```

Poller settings are supplied through `PollerOptions`. `src/index.ts` passes `POLL_TIMEOUT_MS` to `pollTimeoutMs` (default `30000` ms; a finite positive integer no greater than `2147483647`). The deadline applies to a single provider attempt in daemon/manual polling and manual/OAuth/device staged validation; it does not cover an entire sweep or HTTP request. `POLL_MAX_CONCURRENT_GLOBAL` (4), `POLL_MAX_CONCURRENT_PER_PROVIDER` (1), `POLL_MIN_PROVIDER_INTERVAL_MS` (4000), `POLL_MAX_QUEUED_JOBS` (256), and `POLL_ADMISSION_TIMEOUT_MS` (30000) configure the options with the same names. Concurrency and queue size must be positive safe integers; the interval must be an integer in `0..2147483647`, and the admission timeout must be a positive integer in `1..2147483647`. Defaults are used if variables are unset; invalid values are rejected at startup. These are process-local limits; they do not coordinate across multiple processes or guarantee provider API limits.

- **General Daemon vs. User-Initiated Manual Trigger:**
  1. **Background Poller Daemon:** Runs in the server process; collects all registered credential refs with `listAllCredentialsInternal()`, then dispatches them through a bounded shared provider pool.
  2. **User-Initiated Manual Refresh (`POST /api/refresh`):** Polls only credentials belonging to the active session owner's `ownerId`. A user cannot poll or trigger polling of another user's accounts or quotas.
**Mechanism:**
- **Sweep cadence:** The base interval is `5 minutes`; a full daemon poll starts at startup. A periodic trigger that arrives while a sweep is in progress is coalesced with it; subsequent ticks are not queued.
- **Shared dispatch capacity:** The daemon, user-initiated manual refresh, and staged credential validation share an admission pool keyed by canonical provider ID. The default global active-attempt limit is 4, and the per-provider limit is 1. By default, at least 4000 ms separates the start of each provider dispatch. Another ready provider can proceed during that interval; cooldown or queue waiting does not consume active capacity. The interval applies to starting provider attempts, not to all upstream HTTP calls.
- **Bounded waiting:** The shared waiting queue has a default capacity of 256 jobs, and a job's dispatch-wait deadline is 30 seconds; the number of sweep producers per provider group is limited to 17. A credential job is coalesced only within the same credential ID and owner scope. A queued credential is reread with the same owner/id before dispatch; successful reauthorization uses the new token, and a deleted record is skipped. Token/snapshot writes from already-dispatched old jobs are subject to epoch/ownership checks.
- **Cancellation and Capacity Responses:** External cancellation immediately removes a waiting job from the queue; each provider attempt is also subject to the `POLL_TIMEOUT_MS` deadline and caller signal. If an adapter ignores abort, the upstream job may continue but cannot write a late result/callback. A full queue or admission timeout produces HTTP `429`, `Retry-After: 30`, and `errorCode: "POLLER_CAPACITY"`; local admission rejection does not create a new provider error/stale snapshot. Expired/cancelled/foreign OAuth session checks occur before the capacity decision. If staged OAuth code redemption is followed by this capacity error, the session becomes terminal and a new authorization/session is required with `restartRequired: true`. A normal upstream HTTP 429 is not this local signal; it follows provider retry/stale behavior.
- **Deterministic Latest Result:** Among snapshots with the same `fetched_at` timestamp, the highest insertion ID is considered newest. Thus, when timestamps tie, a later successful snapshot takes precedence over an earlier error snapshot; owner-scoped and internal latest/last-good selections follow the same rule.
- **Non-Destructive Error Handling and State Machine (Non-destructive Stale State Machine):**
  When polling fails, the system does not delete telemetry; it preserves the last successful state (`lastGood`):
  - **First Successful Poll:** `health: "healthy"`, `stale: false`, `source: "live"`, `lastGoodFetchedAt: fetchedAt`, `limits: [...]`.
  - **Subsequent Network / Provider Error:** The last successful limits (`lastGood.limits`) are preserved; the report is updated to `health: "stale"`, `stale: true`, `source: "stale"`, `lastGoodFetchedAt: lastGood.fetchedAt`, `error: message`.
  - **First-Ever Error (No Historical Data):** `health: "error"`, `stale: false`, `source: "error"`, `limits: []`, `lastGoodFetchedAt: undefined`, `error: message`.
  - **Successful Poll Again:** The system automatically returns to `health: "healthy"`, `stale: false`, `source: "live"` and clears `error`.
  - **Provider Quota Exhaustion Distinction:** A provider reporting `%100` quota usage (HTTP 200) is normal telemetry, not a polling failure (`health: "healthy"` remains).
  - **Security Boundary:** Raw upstream error bodies or sensitive request data are NEVER stored in snapshots or report objects.
- **Codex / xAI OAuth Session Refresh:** If the usage endpoint returns HTTP `401` and a refresh token is stored, the adapter refreshes the token once, saves the access token and any newly returned refresh token through the vault callback, then retries the usage query once. If no new refresh token is returned, the existing token is retained. HTTP `403`, other errors, or the absence of a refresh token do not trigger a refresh; if refresh or the retry query fails, the stale/error rules above apply. Refresh requests also use the injected `fetch` and `AbortSignal`.
  - **Codex / xAI Safe Reconnection:** An OAuth candidate credential is validated in memory with `validateAndSaveCredential`; the existing record is not changed before validation succeeds. A failed initial connection creates no record; a failed reconnection preserves existing tokens, card color, and usage history. A successful connection updates the existing credential for the same owner, provider, and account label, and saves the validation report; no second initial usage query is made.
  - **Freshness of Queued Credentials:** Before a provider call starts, daemon and user polling reread the credential from the vault with the same owner/id. If successful reauthorization occurred after the queue was created, the new tokens are used; deleted credentials are skipped. Token/snapshot writes from old polls that have already started continue to be rejected by epoch checks.
  - **Manual Replacement vs. OAuth Reconnection:** Callers of `validateAndSaveCredential(ownerId, input, metadataMode)` explicitly choose `replace` or `preserve`. Manual credential POST uses `replace`: the old account's refresh token, OAuth client, project/email/account metadata are not carried over to the new token; metadata produced while validating the candidate is used. OAuth reconnections use `preserve`: validated candidate metadata is merged into the current record, and refresh information not supplied in the same-account flow is preserved. In both modes, failed validation leaves the old credential and history unchanged; card color and credential ID are preserved.
  - **Google Refresh Client Origin:** The complete client ID/secret pair in credential metadata is the source client for the refresh token. Older records without this pair belong to the embedded client; a subsequently configured operator-owned Web client does not change the refresh client for these records.
  - **Provider Attempt Deadline and Cancellation:** Daemon/user polling and staged credential validation (manual credential and OAuth/device validation flows) receive an `AbortSignal` bounded by a deadline and combined with a caller cancellation signal when present. When `POLL_TIMEOUT_MS` expires or the caller cancels, the poller aborts this effective signal and ends the provider wait with `Promise.race`. If an adapter ignores cancellation, the upstream job may continue in the background, but late completions and token callbacks no longer have write authority. Ordinary errors in optional subrequests retain the existing best-effort behavior; abort is not swallowed by these errors, and retry waits are cancellation-aware. Deadline/caller cancellation during normal polling uses the stale/error state machine; staged validation fails without saving the candidate credential or snapshot. Before a successful write, the monotonic deadline is checked, and store-backed authority is also checked when `beforeCommit` is provided. Admission to synchronous commit is the irreversible-write boundary: a commit admitted within the deadline and completed returns success even if synchronous SQL work exceeds the deadline; genuine storage errors propagate. A successful write that has not yet been admitted after the deadline is rejected.
- **Transient Provider Errors:** Exponential backoff (15s, 30s, 60s) is applied for HTTP 429 or transient errors. These provider responses differ from local admission rejection.

#### Reducing Polling and Encryption CPU; Local Synthetic Measurement

In private module state, `crypto.ts` retains a derived key only for the current effective master secret. Every encrypt/decrypt call still runs the existing production master-key guard; if the trimmed secret changes, a new scrypt derivation is performed. This reduces the synchronous scrypt cost repeated on every operation; the key is not exposed to callers, and the encrypted data format/IV/salt/tag and key-rotation behavior do not change.

Using the same payload, 100 local synthetic decrypt measurements took 2433 ms before the cache and 1.666 ms after. A separate measurement with 500 synthetic credentials (250 owners, 2 credentials each, 8 fake provider fixtures, an 80 ms delay per fake call, and a 4000 ms dispatch interval) took 248.228 s for a healthy sweep: 500 calls, peak 4 global / 1 per provider, minimum measured dispatch interval 4000.0276 ms, 500 healthy, 0 stale/error, maximum last-good age 248.145 s, RSS 66 MiB, CPU user 1047 ms / system 422 ms. Under a fault condition where every 50th fake request stalls for 30 seconds until its deadline, the sweep took 326.232 s: 500 calls, peak 4/1, minimum interval 4000.3558 ms, 490 healthy / 10 stale / 0 first-error, 50 seeded stale quota states preserved, maximum last-good age 386.290 s, RSS 68 MiB, CPU user 1637 ms / system 704 ms.

These measurements were taken with fake adapters in a local process; they do not prove real provider calls, VM/production load, 500 real users, upstream limit/429/challenge safety, free-tier readiness, or advertising readiness. An adapter may make multiple HTTP requests/refreshes within a poll attempt. When a fault sweep exceeds five minutes, the next tick joins the in-progress sweep; the following nominal tick may arrive later. Therefore, no claim can be made of freshness every five minutes or multi-user capacity.

---

### Module 4: Passive Proxy Gateway (`src/core/proxy/`)
This is an optional local middleware layer that intercepts OpenAI-compatible requests.

- **Endpoint:** `POST /v1/chat/completions`
- **Operation:**
  1. Forwards the incoming client request to the original upstream provider (supports streaming).
  2. Simultaneously passes the returned HTTP response headers (`anthropic-ratelimit-unified-*`, `x-codex-*`, `x-ratelimit-*`) to the `adapter.parseHeaders()` function.
  3. If quota usage reaches `%100` (or exceeds the threshold), `StorageVault` is updated immediately and the update is pushed to the frontend over SSE.

---

### Module 5: Notification Engine (`src/core/notifier/`)
It sends asynchronous signals to external channels when thresholds are exceeded:

```typescript
export interface AlertEvent {
  provider: string;
  accountLabel: string;
  metric: string;        // "5h_quota", "balance_usd"
  currentValue: number;  // 0.92 or 1.50
  threshold: number;     // 0.90 or 2.00
  resetsAt?: number;
  type: "warning" | "exhausted" | "recovered";
}

export interface Notifier {
  send(event: AlertEvent): Promise<void>;
}
```
- **Supported Channels:**
  1. **ntfy:** `POST https://ntfy.example.com/<topic>` (Zero dependencies, instant notification).
  2. **Telegram Bot:** A Markdown-formatted card via the `sendMessage` API.
  3. **Discord Webhook:** A colored embed message.

---

### Module 6: HTTP API & UI Layer (`src/server/`)

REST routes served with Hono and a server-rendered/authenticated React dashboard. Login/register/recovery pages and explicitly listed invitation/callback routes are public; user data and dashboard APIs require a `usage_session` session.

#### Public Routes
- `GET /login`, `GET /register`, `GET /forgot-password`, `GET /reset-password` → Login, registration, and password recovery pages.
- `POST /api/auth/register` → Creates a user and issues a `usage_session` cookie if open registration policy allows it.
- `POST /api/auth/login` → Issues a `usage_session` cookie on successful login.
- `POST /api/auth/logout` → Deletes the submitted session token and returns an expired cookie.
- `POST /api/auth/password/reset-request` → Accepts `{email}`; with a configured mailer and available queue, returns the same HTTP `202 {success:true}` response for known/unknown addresses. Returns `503 RECOVERY_UNAVAILABLE` if the mailer is not configured or the bounded queue is full. The response does not reveal account/delivery status.
- `POST /api/auth/password/reset-confirm` → Accepts `{token,newPassword}`; atomically consumes a valid token and returns `200 {success:true}`. Does not issue a session cookie; an invalid, expired, or replayed token returns `400 INVALID_RESET_TOKEN`.
- `GET /health` → Status and SQLite integrity check.
- `GET /invite/:token`, `GET /invite`, `POST /api/invitations/:token/accept` → Admin invitation acceptance flow.

#### Session-Protected Routes
- `GET /` → Dashboard; `GET /api/auth/me` → Basic information about the active user.
- `GET /api/usage`, `GET /api/data` → The user's owner-scoped current quota reports (`/api/data` is a compatible alias for the usage response).
- `POST /api/poll`, `POST /api/credentials/:id/poll` → Polls the user's accounts or one credential; the request session is revalidated before every persistent poll write.
- `POST /api/credentials`, `PATCH /api/credentials/:id`, `DELETE /api/credentials/:id` → Create, update, or delete only the session owner's credentials.
- `POST /api/auth/password/change` → Accepts `{currentPassword,newPassword}`; succeeds with `200 {success:true}`, preserving the valid session and cancelling other sessions. An incorrect current password returns `401 INVALID_CREDENTIALS`, a weak new password returns `400 WEAK_PASSWORD`, and a session that later becomes invalid returns `401 UNAUTHENTICATED`.
- `DELETE /api/auth/account` → Accepts `{password}`; a successful response deletes the current cookie. An incorrect password returns `401 INVALID_CREDENTIALS`, the last administrator returns `409 LAST_ADMIN`, and an invalid session returns `401 UNAUTHENTICATED`.
- Provider OAuth initiation, status, device polling, manual completion, and owner-bound session cancellation routes.

#### Admin Routes (`user.role === "admin"`; unauthorized users receive 403)
- `GET /admin` → System administration dashboard.
- `GET /api/admin/stats`, `GET /api/admin/users`, `PATCH /api/admin/users/:id/role`, `DELETE /api/admin/users/:id` → System telemetry and admin user management. The admin management endpoint cannot delete itself; a last-admin guard applies.
- `GET /api/admin/settings`, `PATCH /api/admin/settings/registration` → Registration policy.
- `GET /api/admin/invitations`, `POST /api/admin/invitations`, `DELETE /api/admin/invitations/:id` → Invitation management.


---

## 4. Security Perimeter Architecture (`src/server/security.ts`)

The system is protected against browser- and network-level attacks by a layered security perimeter.

### 4.1. Response Security Headers & CSP
Standard security headers are applied to all HTTP responses:

```typescript
export const MINIMAL_SSR_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");
```

- **Headers:**
  - `X-Frame-Options: DENY` (Clickjacking protection).
  - `X-Content-Type-Options: nosniff` (MIME sniffing prevention).
  - `Referrer-Policy`: normal dashboard `strict-origin-when-cross-origin`; recovery pages override this with `no-referrer`.
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Only in production with `secure: true` or HTTPS).
- **CSP Design Decision and Constraint:** The general SSR policy deliberately uses `'unsafe-inline'` directives for embedded scripts, styles, and Tailwind CDN compatibility; it does not claim nonce protection. Public information pages instead authorize their fixed preference script by its exact SHA-256 hash, computed from the same script constant used to render the page.

### 4.2. CORS Allowlist and Secure Origin Resolution
- **Environment Variables:** `CORS_ALLOWED_ORIGINS` or `USEMETER_ALLOWED_ORIGINS` (a comma- or space-separated list of origins).
- **Same-Origin Default:** If the variable is unset, the system allows only the origin of the incoming request (`requestOrigin`).
- **Wildcard Prohibition for Credentialed Requests:** When `allowCredentials: true` (`usage_session` cookie) is active, `*` (wildcard) is strictly rejected (`false`) in accordance with RFC 6454.

### 4.3. Secure Client IP Resolution (`TRUST_PROXY`)
- **Default Behavior:** `trustProxy` is disabled (`false`). Client-supplied `X-Forwarded-For` or `X-Real-IP` headers are **always ignored** to prevent IP spoofing and rate-limit bypass; the direct socket remote address is used.
- **Reverse Proxy Support:** If the system runs behind Nginx, Caddy, or Cloudflare, `TRUST_PROXY=true` or `TRUST_PROXY=1` must be set. In this case, the leftmost valid client IP address in the `X-Forwarded-For` chain is safely extracted.

### 4.4. Bounded In-Memory Rate Limiter
The RateLimiter stores at most 10,000 keys, applies a sliding window, and supports the deterministic `now()` seam:
- **Authentication (`auth`):** `5/minute/IP` (`POST /api/auth/login`).
- **Registration/Joining (`registration`):** `5/minute/IP`; registration and invitation acceptance use the same IP bucket.
- **Manual Polling (`manualPoll`):** `1/30 seconds/user+credential`; `POST /api/poll` uses a single bucket for all credentials per user.
- **OAuth Device Polling (`oauthDevicePoll`):** `30/minute/user+flow`.
- **Password Change (`passwordChange`):** `3/15 minutes/user+IP`.
- **Password Recovery Request (`passwordResetRequest`):** `5/hour/IP` and also `5/hour/SHA-256(normalized email)`.
- **Reset Confirmation (`passwordResetConfirm`):** `5/15 minutes/IP`.
- **Self-Deletion (`accountDelete`):** `3/15 minutes/user+IP`.

Rate limits on new password/account routes are applied before expensive password verification/hashing. On limit exceeded, HTTP `429` and a `Retry-After` header are returned; API clients use the `RATE_LIMITED` code.

#### 4.4.1. Bounded OAuth Attempt Lifecycle

- The shared `OAuthSessionStore` in `src/core/oauth/session-store.ts` covers web/device attempts and reservations that are still awaiting a provider response. There are **5** occupied slots per user and **1000** total per server instance; active attempts are not evicted to make room. This limit is separate from the request-per-minute rate limit.
- Capacity is reserved before a provider initiate request or callback listener is opened. When full, HTTP **429**, `Retry-After: 60`, and `errorCode: "OAUTH_CAPACITY"` are returned. A start failure/cancellation releases the reservation; if the request connection is closed before a response arrives, upstream work is also cancelled via the session signal.
- The pending duration is capped at **10 minutes**; shorter provider durations are preserved for device flows, longer ones are capped at 600 seconds, and the effective `expiresIn` is returned to the client. This deadline limits the pending session until one-time commit admission.
- A terminal success/error result is retained for **60 seconds**. For a pending attempt that expires before commit admission, its terminal result is removed at the original deadline + 60 seconds; an admitted synchronous commit becomes terminal on completion/error and its result is retained for 60 seconds from then. Unref'd automatic timer cleanup runs even without requests and stops when the store is empty.
- Device binding is scoped to provider + code/UUID + owner. An unknown, foreign, expired, cancelled, or replayed binding is rejected with the same 404 without an upstream poll. A second request while the same owner's poll is in progress returns `pending`; there is no repeated token exchange/save.
- Every successful initiate response contains a `sessionId`. The owner can delete a pending or terminal slot with `DELETE /api/oauth/sessions/:sessionId` (200); a foreign/unknown slot returns 404. Pending work can be cancelled before admission; `cancel()` cannot undo an admitted synchronous commit. This short call stack does not yield to another HTTP request or create an externally long-lived cancellation exception. Google/Devin state, PKCE, frozen-client, and single-use protections remain in force; terminal responses or public projections do not expose verifier/token/client secrets.
- The cancellation/expiry signal is propagated to OAuth initiate/poll/exchange/profile requests, the loopback listener, and candidate usage validation. After provider I/O and candidate validation finish, `beforeCommit` uses the one-time `admitCommit()` check to admit only the same current, owner-bound, claimed, pending, unexpired session immediately before the core commit; there is no `await` or provider I/O between admission and SQL/epoch/snapshot writes. This is not a long-lived lease: OAuth pending expiry/cancellation cannot retroactively fail the same admitted synchronous write; `complete`/`fail` clears admission and starts the normal 60-second terminal result. The poller's separate monotonic attempt deadline is still checked before commit; if that gate rejects, SQL does not start and the failure becomes terminal normally. Expiry before admission writes no candidate credential/snapshot.
- Google/Kimi validation token refreshes also use the same injected `fetch`/session signal. Cancellation is rejected before token/metadata mutation or the refresh callback; a cancelled refresh does not fall back to the normal access token or start a second usage request.
- Password change, reset, self-deletion, or admin deletion cancels the target user's pending OAuth attempts and poller/provider jobs. Request/session owner authority is revalidated after every `await` and immediately before a persistent credential or poll write; a late callback/token refresh from a cancelled request cannot write. A synchronous write admitted by `admitCommit()` is not retroactively cancelled.
- Callback teardown closes only its own captured server instance; an old timer/abort cannot close a newer listener on the same port. This does not resolve hosted-callback compatibility for other loopback-only providers.
- Browser modal close/back/restart/error and unmount cancel the known session with owner-scoped DELETE. If the initiate response has not arrived, the HTTP request continues with a short 12-second client deadline: the `sessionId` in a late response from the old run is deleted, and the new flow/UI is unaffected. Poll/manual requests are aborted immediately; unmount clears the generation and poll timer. EN/TR capacity, expiry, retry, and error messages are localized.
- The test clock is the single `ServerOptions.oauthNow` seam; the old Google-only clocks/maps have been removed. In Devin/Cursor usage validation, discovered identity names are persisted in provider-label mode; manual user labels remain input-bound.

#### 4.4.2. Hosted OAuth Completion Modes

- Claude, Gemini CLI, and Z.ai retain their registered loopback redirect URIs; no fixed-port listener is opened on the server. Those flows require the user to provide the full return URL from the browser to their own attempt. Claude also accepts a state-carrying `code#state` input.
- OpenRouter uses [first-party S256 PKCE](https://openrouter.ai/docs/guides/overview/auth/oauth) with a same-origin `/api/oauth/openrouter/callback`. The server derives the callback origin from the request URL and, only when `TRUST_PROXY=true` or `1`, the existing trusted forwarded-protocol/host convention; it does not accept a browser-supplied redirect target. Non-loopback callbacks require HTTPS, so TLS-terminating reverse proxies must supply trusted HTTPS origin headers. The flow binds the callback to the owner’s bounded session, sends a CSPRNG `state` that OpenRouter echoes unchanged, exchanges the callback code with the stored PKCE verifier, and stages validation before one-time commit admission. No authorization code or callback URL is pasted. An API key is also supported; the provider remains `synthetic_only`.
- The shared authenticated `POST /api/oauth/manual` body is `{sessionId, callbackInput}` for manual callback providers; provider, redirect URI, and verifier are selected from the session. OpenRouter completes through its public callback route instead. Google embedded URL paste and optional custom Web public callback behavior are preserved.
- Manual URL mode checks exact origin/path/state, code XOR error, and duplicate parameters; the pasted URI is not fetched. Public OAuth callbacks parse unique code/state or provider-error parameters, resolve only a server-created state-bound session, and enforce its owner authority, expiry, one-time claim, cancellation, staged validation, and commit admission.
- A terminal attempt submitted to the generic manual endpoint returns HTTP `400` when its owner is known; an unknown or foreign `sessionId` returns HTTP `404`. The unauthenticated OpenRouter callback returns HTTP `400` for invalid, expired, foreign-state, or replayed callback state and does not expose secrets.
- Failed exchange/validation preserves the existing credential, metadata, accent, and snapshot history. Manual callback inputs remain localized for providers using that mode; automatic OpenRouter completion reports success or failure in the returned tab. Synthetic exchange tests do not prove real provider-account or quota compatibility.




### 4.5. At-Rest Data Encryption (Metadata Encryption) and Two-Phase Rollout Contract

The `metadata` column for provider credentials (OAuth `refreshToken`, username, access scopes, etc.) is encrypted at the database level.

1. **Encrypted Envelope Format:**
   - Encrypted metadata is stored in the SQLite `credentials.metadata` text column as the following version-tagged JSON envelope:
     ```json
     {"$vault":1,"ciphertext":"<hex>","iv":"<24-hex>","tag":"<32-hex>"}
     ```
   - Algorithm: **AES-256-GCM** (the master key is derived from `USAGE_MASTER_KEY` using scrypt).
   - Every write generates a cryptographically independent random 12-byte (24-hex-character) IV (`randomBytes`); even if the same metadata is written again, the ciphertext and IV differ each time.

2. **In-Memory Interface Contract:**
   - `StorageVault` public methods (`saveCredential`, `updateCredentialTokens`, `listCredentials`, `getCredential`) continue to expose `StoredCredential.metadata` in memory as a decrypted object (`Record<string, unknown>`); no changes are required in calling layers.

3. **Dual Reader & Fail-Closed Isolation:**
   - The reader transparently reads both legacy plaintext JSON data and the `$vault: 1` envelope.
   - On key mismatch, malformed ciphertext, or an invalid envelope, the system does not silently return `undefined`; it stops the operation immediately (fail-closed) and does not leak plaintext data into logs.

4. **Write Policy:**
   - When the `CREDENTIAL_METADATA_ENCRYPTION` environment variable is unset and the schema is `PRAGMA user_version = 1` (Phase 1 compatibility release), new writes are stored as backward-compatible plaintext JSON.
   - When `CREDENTIAL_METADATA_ENCRYPTION=enabled` is set OR the database schema is already at `user_version >= 2`, all new writes (`saveCredential`, `saveCredentialInternal`, `updateCredentialTokens`) must write an encrypted envelope.

5. **Atomic and Idempotent Schema Migration (v1 -> v2 Migration):**
   - When the environment variable is `CREDENTIAL_METADATA_ENCRYPTION=enabled` and the database is at `user_version < 2`, migration is automatically triggered during `StorageVault` initialization (`migrateCredentialMetadata()`).
   - Migration runs in a single SQLite transaction (`transaction.immediate()`); all existing plaintext `metadata` rows are converted to envelopes and `PRAGMA user_version = 2;` is set.
   - During migration, the credential records' `created_at`, `updated_at`, `owner_id`, `secret`, `iv`, and `tag` fields, and related `usage_snapshots` records are NEVER changed.
   - On parse or encryption failure, the entire transaction is rolled back; partial row updates or a database version increment are prevented.

6. **Two-Phase Production Rollout and Rollback Assurance (Rollout & Rollback Contract):**
   - **Phase 1 (Reader-Only Staging):** Deploy an image containing the dual-reader capability in `vault.ts`; do not yet add the environment variable, and do not roll out Kimi empty-quota or UI changes in this phase. The database remains at `user_version = 1`. Tag the compatible image and take a fresh backup.
   - **Phase 2 (Full Release & Migration):** Deploy the full release with `CREDENTIAL_METADATA_ENCRYPTION=enabled`; the database migrates to `user_version = 2` and all new OAuth tokens (including Kimi) are stored encrypted.
   - **Rollback:** If rollback from Phase 2 to the Phase 1 image is required, the dual reader in the Phase 1 image can directly decrypt `user_version = 2` envelopes; there is no need to restore the old database backup, and no data loss or quota interruption occurs.

7. **SQLite WAL Plaintext Residue and Checkpoint Plan (Infra Notice):**
   - On systems running in SQLite WAL mode, plaintext row pages from before migration may remain in the database's `-wal` file for a while.
   - Immediately after the Phase 2 deployment and before retiring old backups, the system administrator should run `PRAGMA wal_checkpoint(TRUNCATE);` or ensure the WAL file is reset by a controlled container restart.

## 5. Admin Invitation System and User Onboarding (Admin Invitation Onboarding)

Provides secure user onboarding in private deployments where public registration is disabled.

### 5.1. Invitation Lifecycle and Rules
1. **Admin Creation Only:** Only users with the `admin` role can create invitations (`POST /api/admin/invitations`).
2. **Cryptographic Token and One-Way Hash:**
   - The client receives a 32-byte cryptographically secure random string (`crypto.getRandomValues`) as the `token`.
   - The raw token is NEVER stored in the database (`invitations` table); only the `sha256(token)` digest (`token_hash`) is stored.
3. **Single-Use and 24-Hour Validity:**
   - Each invitation expires after 24 hours (`86400000` ms) (`expired`).
   - An accepted invitation is marked with `accepted_at` and cannot be reused.
   - The admin may revoke an invitation at any time (`DELETE /api/admin/invitations/:id` -> `revoked_at`).
4. **Strict Email Binding:**
   - When creating an invitation, the admin must specify a valid target email address (`email`); anonymous or email-free open invitations cannot be created.
   - On the acceptance form (`/invite/:token`), the email field is locked as read-only and registration is completed directly with that email (`COLLATE NOCASE`).
5. **Registration Bypass:**
   - Even if the admin has disabled public registration in system settings (`isRegistrationAllowed() === false`), a user with a valid invitation token can register successfully.
6. **Email Delivery Boundary (No SMTP):**
   - useMeter does not contain an SMTP server or outbound email delivery infrastructure.
   - The admin copies the created invitation link (`/invite/:token`) from the dashboard and sends it to the user through external secure channels.
7. **Bounded and Low-Cost Invitation Acceptance:**
   - The public acceptance endpoint shares the `registration` rate limit with public registration; when exceeded, it returns HTTP 429 and `Retry-After`. Invitation acceptance is independent of the registration-closed setting, but not exempt from rate limiting.
   - `AuthService.acceptInvitation` checks the invitation's existence, acceptance/revocation status, and expiration using the token hash before expensive password hashing. Invalid, expired, revoked, or reused invitations are rejected with the same generic error.
   - The pre-check is only a cost optimization. After generating the password hash, `acceptInvitationAtomic` revalidates the same validity conditions within a transaction; an intervening revocation/expiry or concurrent acceptance cannot create a second user.

## 6. Operational Backup, Monitoring, and Synthetic Load Exercise

### 6.1. Automated Secure SQLite Backup

- `deploy/backup/usemeter-backup.service` and `.timer` run around 03:30 UTC every day under the `murat` user's **systemd user manager**; no root service or root shell is required.
- `usemeter-backup.sh` uses SQLite `VACUUM INTO` directly in a one-off Compose/Bun process, without starting `StorageVault` for the live database. It captures committed WAL data as a consistent snapshot; it does not copy the `usage.db` file alone or explicitly run `wal_checkpoint` or in-place `VACUUM` on the source. It handles SQLite WAL locking and preserves the logical contents of the source database.
- The snapshot schema must be exactly `PRAGMA user_version = 2`, `quick_check = 'ok'`, and `integrity_check = 'ok'`. The host backup is owned by `murat` with mode `0600`; the backup directory has mode `0700` (`umask 077`). The backup is not published as a named persistent file until validation is complete.
- Retention keeps all files from the last 7 days, then the newest file for each ISO week no older than 28 days; older files are removed. Pruning occurs only after the new backup passes a restore drill.

### 6.2. Isolated Restore Drill

`usemeter-restore-drill.sh BACKUP_FILE` validates the candidate in a separate container with `--network none`, a read-only root filesystem, and a read-only bind mount. This container does NOT mount the production volume, and does not run `src/index.ts`, `StorageVault`, migrations, the poller, or providers. It opens the candidate through a read-only/query-only SQLite connection; checks the schema version, `quick_check`, `integrity_check`, credential/snapshot counts, and the `$vault: 1` structure of every encrypted metadata envelope. The drill is not an actual live restore or a credential decryption test using the master key; there is no path to overwrite the production DB.

### 6.3. Admin Metrics and Thresholds

`GET /api/admin/metrics` is accessible only after the existing admin authorization. The response includes main DB and WAL physical sizes, filesystem free space/usage ratio, SQLite free-page count, snapshot and active credential totals, quick integrity health, poller running/sweep status, last sweep duration, and the count of consecutive failed/degraded sweeps. Thresholds:

- Disk usage `>= 90%` → `DISK_USAGE_HIGH`.
- Poller stopped → `POLLER_STOPPED`; at least 3 consecutive bad/failed sweeps → `POLLER_FAILURES_CONSECUTIVE`.
- Integrity failure → `DATABASE_INTEGRITY_FAILED`.
- Mail socket configured but unreachable → `MAIL_BRIDGE_UNAVAILABLE`; if the socket is not configured, status is `disabled`.

The mail bridge probe only connects to the Unix socket and closes the connection; it does not send email content/token or run sendmail. Alert codes are visible in the admin response; external email/webhook notification targets are not part of this contract. The public `/health` endpoint retains its existing small readiness/integrity response.

### 6.4. Synthetic Concurrent Load Test

`deploy/bench/synthetic-load-test.ts` sends synthetic GET traffic to the `/health`, `/api/data`, `/api/providers/catalog`, `/forgot-password`, and `/privacy` routes. The default scenario is 1,000 requests/50 concurrent workers; concurrency is limited to 50–100. It measures p50/p95/p99 latency, throughput, HTTP status/error ratio, and starting/peak/ending RSS; the expected error rate is `%0`.

Only a `http://127.0.0.1` target is accepted; redirects are not followed, and execution is rejected if proxy environment variables are set. Session cookies belonging to at least two distinct synthetic staging users are required; a `/api/auth/me` precheck verifies that the users are different, and cookies/user IDs are not written to output. The harness does not create users, call provider adapters, or connect outside loopback. The benchmark is not run with real production user cookies; RSS measurements alone neither prove nor disprove a possible memory leak.

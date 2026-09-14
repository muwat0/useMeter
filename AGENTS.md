# Repository Guidelines

## Project Overview

useMeter is a self-hosted Bun/TypeScript dashboard for consolidating AI-provider balances, credits, quotas, reset windows, and polling errors. It stores encrypted credentials locally, normalizes provider-specific responses, persists usage snapshots, and serves a Hono API plus server-rendered browser UI.

## Architecture & Data Flow

- `src/index.ts` is the composition root: it reads runtime environment variables, creates `StorageVault`, `ProviderRegistry`, `PollerEngine`, and the Hono server, then starts background polling.
- `ProviderAdapter` is the provider seam. Each adapter implements `supports()` and `fetchUsage()` and may implement `parseHeaders()` for passive rate-limit data. Provider wire formats stay inside `src/core/providers/`; consumers receive normalized `UsageReport` objects.
- `PollerEngine` resolves an adapter by credential provider, fetches a report, persists a snapshot, and notifies listeners. It coalesces concurrent polls per credential and staggers sequential polling. When a poll fails after a prior successful poll, it non-destructively retains the last successful limits and emits a degraded report (`health: "stale"`, `stale: true`, `source: "stale"`, with `lastGoodFetchedAt` and `error`). If a credential has never succeeded, it emits `health: "error"` (`source: "error"`, `stale: false`, empty limits). Real quota exhaustion reported by the provider (HTTP 200) remains `health: "healthy"` and is never treated as a transport/polling error.
- `StorageVault` owns SQLite schema, credential CRUD, AES-256-GCM secret encryption/decryption, snapshot persistence, latest-report retrieval, and `quick_check` health validation. Credentials are upserted by provider plus account label.
- `src/server/app.ts` receives injected vault/poller/registry dependencies and exposes health, usage, credential, polling, OAuth, and dashboard routes. New credentials are initially polled; failed initial validation is rejected and removed.
- OAuth modules isolate PKCE/device-code/callback/token exchange mechanics from provider usage adapters. Local callback servers bind to loopback and validate state/timeouts.
- The browser dashboard consumes `/api/data`, `/api/credentials`, and `/api/poll`; client rendering handles language, sorting, card accents, and error localization.
- `docs/SPEC.md` and ADRs describe the intended deep-module and hybrid polling/proxy design. Treat missing modules such as proxy/notifier as planned seams, not implemented runtime behavior.

## Key Directories

- `src/core/providers/`: normalized provider adapters and registry wiring.
- `src/core/oauth/`: OAuth authorization, callback, refresh, and token-exchange helpers.
- `src/core/storage/`: encrypted SQLite vault and usage snapshot persistence.
- `src/core/poller/`: background polling lifecycle and single-flight behavior.
- `src/server/`: Hono routes and the server-rendered dashboard HTML/client script.
- `tests/`: Bun unit tests and in-process Hono integration tests.
- `docs/`: technical specification and accepted architecture decisions.

## Development Commands

```sh
bun install
bun run dev              # bun --watch src/index.ts
bun run start            # bun run src/index.ts
bun test
bun x tsc --noEmit       # direct strict typecheck; no package script exists
```

`package.json` does not define `build` or `lint` scripts. Do not assume npm/yarn/pnpm commands or a compiled build step. Use Bun commands and keep `bun.lock` authoritative.

## Code Conventions & Common Patterns

- Use native ESM imports and strict TypeScript. Preserve `noUnusedLocals`, `noUnusedParameters`, `noFallthroughCasesInSwitch`, and `noPropertyAccessFromIndexSignature` compatibility.
- Keep domain contracts in `src/types.ts`; use `UsageUnit`, `UsageStatus`, `UsageWindow`, `UsageAmount`, `UsageLimit`, and `UsageReport` rather than provider-shaped objects outside adapters.
- Add a provider by implementing `ProviderAdapter`, isolating endpoint/auth/parsing logic in its adapter, and registering it explicitly in `src/core/providers/registry.ts`. `supports()` should accept only deliberate provider aliases.
- Accept `FetchContext` in provider fetchers and use `ctx.fetch`/`ctx.signal` so network behavior is injectable and cancellable in tests.
- Use `StorageVault` for all credential and snapshot persistence. Never log, commit, or expose plaintext API keys, OAuth refresh tokens, cookies, or raw provider payloads.
- Preserve error context in `UsageReport.error`; convert provider failures into user-facing localized categories at the UI boundary. For accounts with preserved prior data (`stale: true` / `health: "stale"`), the dashboard displays an amber cached warning notice alongside the preserved limits and the last successful poll timestamp (`lastGoodFetchedAt`). First-ever poll failures (`health: "error"`) display a red error notice with empty limits. Real exhausted quota (`usedFraction >= 1.0`) is healthy telemetry and must not trigger stale/error warning states.
- Keep OAuth callback/state validation and token refresh inside `src/core/oauth/`; server routes should orchestrate saving credentials and triggering initial validation.
- For browser UI changes in `src/server/app.ts`, remember that the dashboard client is embedded inside a server template literal. Avoid unescaped `</script>` sequences and fragile regex/template-literal escapes; validate the extracted client script syntax.
- Keep language-dependent strings in the `I18N` dictionaries or translation helpers. Do not add hardcoded user-visible Turkish/English text to rendering paths when a translation key or helper is appropriate.
- Card/account presentation state is client-side; persisted account label/accent changes go through the credential `PATCH` API. Keep sorting, drag state, and edit-mode transitions consistent with `renderCards()`.
- Enforce response security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, CSP, and conditional HSTS) via `src/server/security.ts`. The CSP must remain compatible with inline SSR scripts, inline theme styles, and the Tailwind CDN.
- Use `createCorsOriginResolver` for CORS origin evaluation backed by `CORS_ALLOWED_ORIGINS` (or `USEMETER_ALLOWED_ORIGINS`). Default to same-origin only; never reflect unverified origins or allow credentialed wildcards.
- Apply bounded rate limiting (`RateLimiter`) using standard policies (`RATE_LIMIT_POLICIES`): `auth` on login, `registration` on public registration, `manualPoll` on poll endpoints, and `oauthDevicePoll` on OAuth status/device polls. Resolve client IP via `resolveClientIp` with `TRUST_PROXY` semantics. Never rate-limit static GET pages or `/health`. Return HTTP 429 with `Retry-After`.
- Manage user onboarding through invitations: admins create, list, and revoke invitations (`/api/admin/invitations`). Raw invitation tokens are returned only once upon creation as `inviteUrl`; invitation listings never expose tokens or hashes. Public invite acceptance (`POST /api/invitations/:token/accept`) creates regular users and works even when public registration is disabled. Invalid, expired, revoked, or replayed tokens return generic 400 responses without disclosing token state.

## Important Files

- `src/index.ts`: runtime entrypoint and defaults (`PORT=3100`, `DATABASE_PATH=data/usage.db`).
- `src/types.ts`: canonical domain types.
- `src/core/providers/adapter.ts`: adapter and fetch-injection contract.
- `src/core/providers/registry.ts`: built-in adapter registration and lookup.
- `src/core/storage/vault.ts`: SQLite schema, encryption-backed credential store, snapshots, integrity check.
- `src/core/poller/poller.ts`: polling, single-flight map, staggering, listeners, error snapshots.
- `src/core/crypto.ts`: AES-256-GCM and master-key derivation.
- `src/core/oauth/`: provider-specific login and refresh implementations.
- `src/server/app.ts`: API routes, OAuth orchestration, SSR dashboard, embedded client UI.
- `src/server/security.ts`: security headers, CSP, CORS origin resolver, rate limiter, and client IP extraction.
- `CONTEXT.md`: canonical domain vocabulary and terminology.
- `docs/SPEC.md`: module seams, normalized contracts, API shape, and intended tracking model.
- `docs/adr/0001-self-hosted-bff-architecture.md`: self-hosted BFF/SQLite decision.
- `docs/adr/0002-dual-engine-tracking-model.md`: active polling/passive header strategy.
- `docs/adr/0003-multi-tenant-session-authentication.md`: multi-tenant session authentication.
- `docs/adr/0004-security-perimeter-and-invitation-onboarding.md`: security perimeter and invitation onboarding.
- `docs/adr/0005-nondestructive-stale-usage-state.md`: non-destructive stale and degraded usage state.

## Runtime/Tooling Preferences

- Bun is required: the code uses `bun:sqlite`, `Bun.serve`, Bun Web APIs, and Bun type declarations.
- Source is ESM (`type: module`) with ESNext target/module and bundler resolution.
- Environment variables: `PORT`, `DATABASE_PATH`, and `USAGE_MASTER_KEY` are core runtime settings. `KIMI_CODE_BASE_URL` and ZAI OAuth override variables are provider-specific.
- `USAGE_MASTER_KEY` must be set for secure deployment. The source fallback is explicitly insecure development behavior.
- SQLite runs with WAL, `synchronous=NORMAL`, foreign keys enabled, and a 5-second busy timeout.
- Runtime databases, SQLite sidecars, `.env` files, and dependencies are gitignored. Keep `data/` out of commits.

## Testing & QA

- Tests use Bun's built-in `bun:test` runner with `describe`, `it`, and `expect`; there is no separate test configuration or coverage script.
- Provider tests use typed synthetic `StoredCredential` fixtures and handwritten injected `fetch` functions returning standard `Response`/`Headers` objects. Test parsing and observable normalized limits, not implementation details.
- Storage tests use `StorageVault(":memory:")` for isolation. Close vaults explicitly in longer tests.
- Server tests construct `createServer(vault, poller, registry)` and call `app.request(...)` without binding a network listener.
- Before delivering source changes, run both `bun x tsc --noEmit` and `bun test`. For dashboard changes, also extract/parse the rendered inline client script and exercise the affected browser interaction; compile success alone does not validate embedded JavaScript.

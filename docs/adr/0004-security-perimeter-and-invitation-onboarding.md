# ADR-0004: Security Perimeter, Reverse Proxy Trust, and Controlled Onboarding via Administrator Invitation

- **Status:** Accepted
- **Date:** 2026-09-15
- **Decision Makers:** Murat
- **Related Documents:** [CONTEXT.md](../../CONTEXT.md), [docs/SPEC.md](../SPEC.md), [ADR-0001](0001-self-hosted-bff-architecture.md), [ADR-0002](0002-dual-engine-tracking-model.md), [ADR-0003](0003-multi-tenant-session-authentication.md)

---

## 1. Context and Problem Statement

After useMeter transitioned to a multi-user private SaaS model (ADR-0003), the need arose to expose the application to the internet or shared networks in self-hosted deployments (for example, home servers, VPSs, cloud servers, or local network gateways). This raised the following concrete security requirements:

1. **Network and Browser Threats:** Clarify the standard response headers and Content Security Policy (CSP) posture against clickjacking, MIME-type spoofing (MIME sniffing), unauthorized iframe embedding, and XSS attacks.
2. **Cross-Origin Resource Sharing (CORS):** Control API requests from external origins and prevent wildcard (`*`) abuse in authenticated requests (with the `auth_session` cookie).
3. **Reverse Proxy IP Detection:** When the system runs behind Nginx, Caddy, or Cloudflare, rate limits must not be applied to the proxy IP instead of the client; however, direct access must not permit IP spoofing through forged `X-Forwarded-For` headers.
4. **Denial-of-Service and Brute-Force Protection:** An in-memory rate limiter is required to prevent DoS and brute-force attacks at authentication, manual quota lookup, and OAuth device-flow endpoints.
5. **Controlled User Onboarding:** In private/corporate environments where public external registration is disabled (`registrationAllowed = false`), provide a secure, time-limited, single-use registration option for users designated by the administrator.
6. **No External Dependency (No SMTP):** To preserve the ease of self-hosted use, the invitation system must not require an external SMTP server, email provider, or API key.

---

## 2. Considered Alternatives

### Alternative A: Invitation System Dependent on External Email (SMTP)
- **Rationale:** In traditional SaaS products, invitations are sent directly to the user's email address as a link.
- **Reasons for Rejection:**
  - **Setup Friction:** Requires self-hosting users to configure an SMTP server (Postfix/Dovecot), a TLS certificate, or an external processor (Resend, SendGrid, Amazon SES); this undermines the lightweight BFF philosophy.
  - **Fragility:** Invitations failing to arrive because of port 25 blocks, difficulties with SPF/DKIM/DMARC configuration, or spam filters would create support overhead.
  - **Decision:** No SMTP layer will be built into the system; the administrator copies the generated invitation link (`/invite/:token`) from the dashboard and forwards it to the user through a trusted channel (Signal, Telegram, internal company chat, etc.).

### Alternative B: Distributed / Redis-Based Rate Limiting
- **Rationale:** Maintain a centralized rate counter in multi-server/cluster architectures.
- **Reasons for Rejection:**
  - useMeter runs as a standalone Bun process on a local SQLite vault (ADR-0001).
  - Adding Redis or an external KV store would unnecessarily increase operational complexity.
  - **Decision:** Implement an in-memory `RateLimiter` using a deterministic clock seam (`now()` injection seam) and a sliding window with a maximum cap of 10,000 keys.

### Alternative C: Strict Nonce/Hash-Based CSP
- **Rationale:** The strictest CSP standard for minimizing XSS risk.
- **Reasons for Rejection:**
  - useMeter uses server-side HTML rendering (SSR), embedded theme/language JavaScript code, and a Tailwind CSS engine loaded via CDN.
  - Generating a nonce or dynamic hash would require a massive refactor of the existing lightweight SSR template architecture and complicate caching/render flows.
  - **Decision:** Implement a pragmatic `MINIMAL_SSR_CSP` containing `script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com` and `style-src 'self' 'unsafe-inline'`; never overclaim in the documentation (claim protection from nonces that do not actually exist).

---

## 3. Decisions Made

### 1. Standard Security Response Headers
Injected globally into all responses via the `src/server/security.ts` module:
- `X-Frame-Options: DENY` (Prevents embedding in iframes on all pages).
- `X-Content-Type-Options: nosniff` (Prevents MIME-sniffing attacks).
- `Referrer-Policy: strict-origin-when-cross-origin` (Preserves privacy on external redirects).
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` (Disables unnecessary browser capabilities).
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Applies one-year HSTS only in HTTPS or `secure: true` environments).

### 2. Pragmatic Content Security Policy (CSP)
- The `MINIMAL_SSR_CSP` policy, fully compatible with current SSR and Tailwind requirements, has been defined:
  ```text
  default-src 'self';
  script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self'
  ```
- No nonce or dynamic script hash is claimed; the use of `'unsafe-inline'` is a deliberate SSR compatibility tradeoff.

### 3. Secure CORS Policy and Prohibition on Wildcards for Authenticated Requests
- Allowed origins are specified via the `CORS_ALLOWED_ORIGINS` or `USEMETER_ALLOWED_ORIGINS` environment variables.
- If the variable is empty, **same-origin by default** applies; no CORS header is emitted for external origins.
- Because useMeter uses session cookies (`auth_session`) (`allowCredentials: true`), wildcard (`*`) use is **strictly rejected** (`isOriginAllowed` -> `false`) in accordance with RFC 6454.

### 4. Strict Reverse Proxy Trust (`TRUST_PROXY`)
- By default, `trustProxy = false`. Client-supplied `X-Forwarded-For` or `X-Real-IP` headers are ignored to prevent IP spoofing; the direct socket remote address is used.
- When the system runs behind a trusted reverse proxy (Nginx/Cloudflare), the leftmost (client) IP in the `X-Forwarded-For` header is safely resolved by setting `TRUST_PROXY=true` or `TRUST_PROXY=1`.

### 5. Bounded In-Memory Rate Limiter (`RateLimiter`)
- A lightweight in-memory rate limiter using a sliding window and holding at most 10,000 unique keys (`maxKeys: 10000`) has been implemented.
- Standard policies:
  - `auth`: `5 requests / minute / IP` (`POST /api/auth/login`).
  - `registration`: `5 requests / minute / IP`; `POST /api/auth/register` and `POST /api/invitations/:token/accept` share the `registration:<IP>` bucket. Applied before body parsing and password hashing.
  - `manualPoll`: `1 request / 30 seconds / user + credential` (`/api/refresh`)
  - `oauthDevicePoll`: `30 requests / minute / user + flow`
- Exceeding the limit returns `429 Too Many Requests` and a `Retry-After` response.

### 6. Administrator Invitation System and Single-Use Onboarding (Invitation Onboarding)
- **Administrator-Only:** Only users with the `admin` role can generate invitations (`POST /api/admin/invitations`).
- **Cryptographic Token Security:**
  - A 32-byte cryptographically secure random string (`crypto.getRandomValues`) is provided to the client.
  - The raw token is NEVER stored in the database (`invitations` table); only a one-way **SHA-256 hash (`token_hash`)** is stored.
- **24-Hour Validity and Single Use:**
  - Invitations expire (`expired`) after 24 hours (`86.400.000` ms).
  - Once accepted, an invitation is locked with `accepted_at` and cannot be used a second time.
  - The administrator can revoke an invitation at any time with one click (`DELETE /api/admin/invitations/:id` -> `revoked_at`).
- **Mandatory Email Binding (Strict Email Binding):** When an invitation is generated, the administrator must specify a valid target email address; useMeter does not support anonymous or unrestricted email-less invitations. The email field on the acceptance form is locked as read-only, and the account is created at registration with this email, case-insensitively (`COLLATE NOCASE`).
- **Onboarding While Registration Is Closed (Registration Policy Bypass):** Users with a valid invitation token can successfully register even when general external registration is disabled in the system (`isRegistrationAllowed() === false`).
- **Pre-Hashing Check (2026-10-12):** During invitation acceptance, a token that cannot be found, has expired, has been revoked, or has already been used is rejected with the same generic error before expensive password hashing. The pre-check is not an authorization decision: after hashing, the atomic transaction checks all conditions again; revocation/expiry/concurrent-acceptance races cannot defeat the single-use guarantee.
- **Shared Onboarding Rate Limit (2026-10-12):** Invitation acceptance and general registration are limited to a total of five requests per IP per minute; using a different token or endpoint does not open a new quota. Exceeding the limit returns HTTP 429 + `Retry-After`; closed registration does not disable invitation acceptance or remove the rate limit.
- **Email Delivery Boundary (No SMTP Boundary):** No email delivery mechanism exists within useMeter. The administrator copies the link from the panel and transmits it to the user through external secure channels.

### 7. OAuth Pending State Boundaries and Cancellation Authority (2026-10-13)

- Web/device state and initiate reservations are kept in a single bounded store: 5 occupied slots per user and 1000 per server instance; reservations, pending sessions, and 60-second terminal results count toward capacity. Capacity is reserved before upstream/listener startup; at the limit, the response is 429/Retry-After60 and `OAUTH_CAPACITY`.
- The pending lifetime is at most 10 minutes, and this deadline is enforced through commit admission; a provider's shorter device TTL is preserved. Expiry and terminal cleanup are handled by an unref timer that does not wait for requests; an empty store does not retain a timer. Temporary sensitive fields such as PKCE/client secret are deleted on terminal/cancellation/expiry.
- Each initiate returns a `sessionId`; `DELETE /api/oauth/sessions/:sessionId` is available only to its owner. Pending work can be cancelled before admission; the store's `cancel()` cannot roll back an admitted synchronous commit. Because the admission phase does not yield, another HTTP handler cannot interpose during this narrow window. Missing/foreign/expired/cancelled/replayed device bindings cannot reach upstream; concurrent polling by the same owner does not perform a duplicate exchange.
- `AbortSignal` is propagated to all relevant upstream and captured callback resources. Once provider I/O and candidate validation are complete, `admitCommit()` grants one-time authority only for the current owner-bound claimed pending session, immediately before the core commit; there is no `await` or provider I/O from admission through SQL/epoch/snapshot writes. This is not a long-lived lease, but a short boundary that prevents OAuth expiry/cancellation from retroactively invalidating the current synchronous commit. `complete`/`fail` clear admission and start the 60-second terminal receipt. A separate poller attempt deadline still applies before SQL; if rejected, the failure is cleanly terminalized, while expiry before admission produces no writes.
- Instead of losing a late initiate response, the frontend receives it under a 12-second deadline and deletes only the old `sessionId`; unmount/run changes do not affect the new flow. Success/failure results are retained for 60-second poll consumption. Hosted loopback topology and general poller capacity are separate open items.


---

## 4. Security and Threat-Model Tradeoffs (Threat Tradeoffs)

| Area | Chosen Approach | Reason for Preference | Known Tradeoff / Risk Constraint |
|---|---|---|---|
| **CSP** | Pragmatic SSR CSP containing `'unsafe-inline'` | Compatibility with existing server-side HTML, theme scripts, and Tailwind CDN | Full script isolation at nonce level cannot be achieved; however, clickjacking and data exfiltration are prevented. |
| **CORS** | Strict allowlist; no `*` for authenticated requests | Prevent sites without authorization from hijacking sessions with the user's `auth_session` cookie | Legitimate tools that consume the API from an external origin must be explicitly listed in `CORS_ALLOWED_ORIGINS`. |
| **IP Detection** | `TRUST_PROXY=false` by default | Prevent clients from bypassing rate limits with forged `X-Forwarded-For` | In deployments behind a reverse proxy, if the `TRUST_PROXY=true` environment variable is forgotten, all requests are attributed to the proxy's local IP. |
| **Rate Limiting** | In-memory sliding window (cap: 10k keys) | Zero dependency on external services (Redis); microsecond latency | Counters reset when the server restarts; applies to a single Bun process. |
| **Invitation Token** | 32-byte random string + SHA-256 in the DB | Prevent plaintext invitation tokens from being obtained in a database breach | If the administrator loses the generated link, the token cannot be recovered from the hash; a new invitation must be generated. |
| **Communication** | Manual link copying (No SMTP) | Eliminate setup friction and spam/reputation risks | The administrator must manually deliver the link to the user through a secure communication channel. |

---

## 5. Consequences and Future Adaptations

- The system has been hardened against standard web attacks when exposed to an external network or serving multiple users on a local network.
- If, in the future, the SSR template engine extracts inline scripts at build time or the application moves to a static SPA separation, the CSP policy can be freed from its `'unsafe-inline'` dependency and upgraded to a strict nonce- or hash-based model.
- Unless multi-server deployment is a target, the in-memory rate limiter and database-level invitation tracking are architecturally sufficient and simple.

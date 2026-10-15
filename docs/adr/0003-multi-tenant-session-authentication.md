# ADR-0003: Private Multi-User Architecture, Argon2id, and Server-Side Opaque Session Management

- **Status:** Accepted
- **Date:** 2026-09-14
- **Decision Makers:** Murat
- **Related Documents:** [CONTEXT.md](../../CONTEXT.md), [docs/SPEC.md](../SPEC.md), [ADR-0001](0001-self-hosted-bff-architecture.md), [ADR-0002](0002-dual-engine-tracking-model.md)

---

## 1. Context and Problem Statement

The system was initially designed for a single-user, local desktop or standalone self-hosted server environment (ADR-0001). However, the use case has expanded, evolving into a **private multi-user SaaS** service layer where multiple trusted users (e.g., family members, coworkers, or engineers sharing infrastructure) can track their own AI account quotas and balances on the same server instance, completely isolated from one another.

The following critical architectural needs have arisen with this transition:
1. **Authentication Mechanism:** A secure authentication layer that can operate with zero external network dependencies, without depending on external third-party services or OAuth providers (e.g., Google, GitHub).
2. **Session Management:** The security and revocation trade-off between client-side stateless tokens such as JWTs (JSON Web Tokens) and server-side opaque sessions.
3. **Data Isolation and Multi-Tenancy:** Row-level tenant isolation (`ownerId`) on the SQLite database to strictly separate each user's credentials and usage data from those of other users.
4. **Preservation of Existing Data and Migration (Legacy Migration):** Migrating credentials and usage records from the single-user era that have no owner (`owner_id IS NULL`) to the new architecture without data loss.
5. **Security Boundaries and Cookie Policy:** Keeping the web panel and data APIs from being publicly accessible, requiring authorization, and establishing a browser-cookie posture against CSRF/XSS threats.

---

## 2. Evaluated Alternatives

### Alternative A: Client-Side Stateless JWT (Stateless JWT)
- **Rationale:** Does not require a session table on the server; horizontal scaling is straightforward.
- **Reasons for Rejection:**
  - **Irrevocability:** When a user logs out (`logout`) or a session is stolen, it cannot be immediately and definitively revoked server-side until the token expires. Maintaining a revocation list (blacklist/denylist) eliminates all the benefits of statelessness.
  - **Secret Key Leakage Risk:** If the JWT signing key is leaked, forged tokens can be generated on behalf of all users.
  - **Unnecessary Complexity:** In a BFF architecture backed by a single SQLite database, a database query already takes microseconds; statelessness offers no practical advantage.

### Alternative B: Login with External Identity Providers (Social / Third-Party OAuth)
- **Rationale:** Eliminates the need for users to remember passwords.
- **Reasons for Rejection:**
  - **External Dependency and Offline Availability:** One of the system's core principles is zero external API dependency and the ability to work even on a local network/offline. Requiring Google/GitHub OAuth violates this principle.
  - **Complex Setup:** Requires every self-hosting user to create an OAuth Client ID/Secret in Google Cloud Console or GitHub Developer settings, dramatically increasing setup friction.
  - *Note:* OAuth connections used to query AI provider quotas (OpenAI, Google Antigravity, Claude) are completely independent of the system's own user login.

### Alternative C: Password + Server-Side 32-Byte Opaque Session Token (Selected)
- Users register/log in with an email and password.
- Passwords are hashed using Bun's native Argon2id engine.
- On login, the client is issued a cookie containing a 32-byte cryptographically random opaque string (`auth_session`).
- Only the token's SHA-256 digest is stored in the database.
- At logout, the session row is deleted, providing immediate and definitive revocation.

---

## 3. Decisions

### 1. Password Security: Bun.password Argon2id
- User passwords are hashed with the Bun runtime's built-in `Bun.password` Argon2id algorithm (`algorithm: "argon2id"`).
- Passwords are limited to a minimum of 12 and a maximum of 256 UTF-8 characters/code units, and are subject to deterministic validation.
- Emails are canonicalized system-wide using `trim().toLowerCase()` and are unique regardless of case (`COLLATE NOCASE UNIQUE`).
- On failed login, a generic error message (`Invalid email or password`) is thrown to prevent an attacker from determining whether an email is registered in the system (User Enumeration Protection).

### 2. Stateful Opaque Sessions and SHA-256 Hashing
- The session token issued to the client is derived from 32 cryptographically random bytes (`crypto.getRandomValues`).
- The plaintext token is NEVER stored in the database's `sessions` table; only its one-way **SHA-256 hash (`token_hash`)** is stored. Thus, even in the event of a database snapshot or leak, active sessions cannot be impersonated.
- The session lifetime (TTL) is **30 days** (`2592000` seconds).
- When a user logs out (`logout`), the session record in the database is deleted immediately.

### 3. Cookie Policy and CSRF/XSS Protection
The session token is sent to the client in a `Set-Cookie` header:
- `HttpOnly: true` → In-browser JavaScript cannot access the token (XSS attacks).
- `SameSite: Lax` → Prevents forged requests triggered by third-party sites (CSRF) while preserving the session when the user arrives at the site by clicking a direct link.
- `Path: /` → Applies throughout the application.
- `Secure: true` → Required for HTTPS and in production environments.

### 4. SQLite Row-Level Tenant Isolation (Tenant Boundary)
- An `owner_id` (foreign key -> `users.id`) column has been added to the `credentials` and `usage_snapshots` tables.
- Referential integrity is enforced with `PRAGMA foreign_keys = ON;`.
- Indexes are defined on `(owner_id, provider)` and `(owner_id, recorded_at)`.
- **Data Access Contract:** All data read, update, and delete APIs in the application layer must take an `ownerId` parameter. No user can see or manage another user's credentials, quotas, or usage reports.
- **Protected Surface:** The dashboard page (`GET /`) and all data endpoints (`/api/usage`, `/api/credentials`, `/api/refresh`) require a valid session; anonymous public data access is strictly prohibited.

### 5. Atomic Claiming of Legacy Data (First-User Legacy Claim)
During the transition from the single-user version to the multi-user architecture:
- Existing credentials and usage snapshots are not deleted (`owner_id` initially remains `NULL`).
- The first actual (non-system) user to register (the first row in the `users` table) atomically claims all ownerless records within a single database transaction:
  ```sql
  UPDATE credentials SET owner_id = :firstUserId WHERE owner_id IS NULL;
  UPDATE usage_snapshots SET owner_id = :firstUserId WHERE owner_id IS NULL;
  ```
- After this operation, no ownerless records remain in the system; users who register later can never see this legacy data.

### 6. General Background Daemon vs Owner-Scoped Manual Trigger
- **Background Poller (Poller Daemon):** To keep the quotas of all provider accounts up to date, the continuously running background service reads and updates all credentials via the explicitly defined sole internal method, `listAllCredentialsInternal()`. This is an internal server-side process and is not exposed through external HTTP APIs.
- **User-Triggered Manual Refresh (`POST /api/refresh`):** Refresh requests initiated by a user from the web panel are strictly limited to credentials owned by the authenticated user (`ownerId`).

### 7. Explicitly Out of Scope (Explicit Out-of-Scope)
The following enterprise/public SaaS features are intentionally out of scope:
- Multiple roles / authorization matrix (RBAC).
- Organizations, teams, or account sharing between users.
- Password reset and email verification emails (to avoid requiring external SMTP).
- Payment, subscription, and billing layers (e.g., Stripe).

---

## 4. Consequences and Trade-offs

### Benefits (Pros)
1. **Complete Isolation:** Each user sees only their own AI accounts and quotas.
2. **Seamless Revocation Security:** The server-side session table ensures that a session ends immediately upon logout.
3. **Zero External Dependencies:** No external identity provider or email service is required; the system runs completely isolated using Bun's native capabilities.
4. **Zero Data Loss:** Historical quotas and configured credentials from the single-user system are preserved by transferring them to the first user.
5. **Attack Resistance:** `HttpOnly` + `SameSite: Lax` cookies minimize XSS and CSRF risks.

### Trade-offs (Cons)
1. Every authentication request performs an indexed read from the `sessions` table (under 0.1 ms in SQLite's in-memory cache).
2. Expired session rows must be cleaned up periodically (using a simple timer or during login).

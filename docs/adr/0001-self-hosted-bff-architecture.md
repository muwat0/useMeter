# ADR-0001: Self-Hosted Backend-for-Frontend (BFF) and SQLite Architectural Choice

- **Status:** Accepted
- **Date:** 2026-09-13
- **Decision Makers:** Murat

---

## 1. Context and Problem Statement
We are designing a web application that consolidates the remaining balances, credits, and quota usage across the user's various AI services (OpenRouter, DeepSeek, OpenAI, Anthropic, Cursor, Google Antigravity, etc.) in a single screen.

When designing this system, there are two fundamental architectural dilemmas:
1. **Client Architecture:** Should it be a static web page that runs only in the browser (Pure Frontend / SPA), or a Backend-for-Frontend (BFF) that includes a server layer?
2. **Service Model:** Should it be a public, multi-user SaaS, or a personal/isolated Self-Hosted application?

---

## 2. Considered Alternatives and Constraints

### Alternative A: Pure Frontend (Pure SPA / PWA)
- **Constraint 1 (Definitive CORS Barrier):** OpenAI, Anthropic, Google Cloud, Cursor, and ChatGPT API endpoints do not allow cross-origin requests (`cross-origin`) from browsers (they do not return the `Access-Control-Allow-Origin` header). The browser blocks these requests at the network level.
- **Constraint 2 (Security Vulnerability):** The user's sensitive API keys (`sk-admin-...`), OAuth `refresh_token`s, and session cookies would have to be stored in the browser's `localStorage` or `IndexedDB`. This creates a critical security vulnerability in the face of XSS or malicious browser extensions.
- **Constraint 3 (No Background Continuity):** Polling stops when the browser tab is closed. Tracking 5-hour rolling windows, reset counters, and Telegram/ntfy alerts when quota reaches 90% would not work.
### Alternative B: Public Multi-User SaaS
- **Constraint 1 (IP-Based Blocking):** When hundreds of users' Claude and ChatGPT `/usage` queries originate from a single egress IP address of a centralized SaaS server, providers' Cloudflare WAF and IP rate-limiter engines (`HTTP 429`) lock out the entire service.
- **Constraint 2 (Legal and Security Burden):** Hosting other users' sensitive keys creates KVKK/GDPR and data breach risks.

---

## 3. Decision

1. **Self-Hosted Deployment:** The application will be designed to run on the user's own hardware (local desktop, Linux VPS, cloud VM, or Docker). Since each user will make queries from their own home/server IP, the risk of being affected by providers' IP blocking is eliminated.
2. **Backend-for-Frontend (BFF) Layer:**
   - **Runtime:** **Bun / Node.js (TypeScript)**.
   - **Web Framework:** **Hono**. It is small, fully compliant with web standards, has zero external dependencies, offers high performance, and has strong Server-Sent Events (SSE) / WebSocket support.
   - **Database and Security:** **SQLite (in WAL mode)**. It does not require an external database server (PostgreSQL/MySQL); it can be backed up as a single file. Sensitive credentials (API key, OAuth refresh token) are stored encrypted in the database using **AES-256-GCM**.
3. **User Interface (Frontend):**
   - **Technology:** **Vite + React + Tailwind CSS**.
   - **Communication:** Communicates with the backend via local REST and SSE/WebSocket; the browser never sends requests directly to AI providers.

---

## 4. Consequences and Trade-offs

### Benefits (Pros)
- **Zero CORS Issues:** There are no CORS restrictions in Server-to-Server communication.
- **High Security:** API keys are never sent to the browser; they are kept in an encrypted vault on the server.
- **Uninterrupted 24/7 Tracking:** The background daemon monitors quotas, records historical trends, and sends notifications (Telegram/ntfy) when thresholds are exceeded, even while the browser is closed.
- **Low Resource Consumption:** The Hono + SQLite combination consumes < 30 MB RAM when idle; it adds no cost to the user's existing home/server infrastructure.

### Trade-offs / Burdens (Cons)
- Requires the user to run the application as a Docker container or local service (it is not as effortless as a static HTML page that opens with one click).

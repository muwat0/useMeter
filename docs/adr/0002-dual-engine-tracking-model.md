# ADR-0002: Dual-Track (Hybrid) Quota and Balance Tracking Engine

- **Status:** Accepted
- **Date:** 2026-09-13
- **Decision Makers:** Murat

---

## 1. Context and Problem Statement
There are two different methods for collecting quota and balance data from AI services:
1. **Active Polling:** The server periodically sends requests to the provider's balance/quota endpoints.
2. **Passive Header Interception:** Listening to the HTTP response headers returned by the provider during the user's normal model calls (inference).

Both methods have critical shortcomings when used on their own:
- **Active Polling Only:** If run frequently, it hits IP rate limits on providers' usage endpoints (`HTTP 429`); if run infrequently, it may not detect sudden quota consumption during intensive coding for 5–15 minutes (delayed alert).
- **Passive Interception Only:** It does not update unless the user makes a model call; it cannot determine when the 5-hour rolling window resets or the account's exact remaining dollar balance.

---

## 2. Decision

The system will implement a **Dual-Track (Hybrid) Tracking Engine**:

### Track A: Active Poller
- **Task:** Retrieve net cash balances, account plan types, and static quota status.
- **Operating Interval:** Configurable base period of 5–15 minutes.
- **Critical Safeguards:**
  1. **Jitter:** A random deviation of **±25%** is added to account polling intervals. This prevents multiple accounts from hitting the same provider at the same millisecond.
  2. **Single-Flight Promise Coalescing:** New requests for an account are held while a request is already in progress; no duplicate network call is made.
  3. **Backoff:** If an endpoint returns 429 or 500, the polling interval for that account is temporarily extended and the last successful data (stale cache) continues to be displayed.

### Track B: Passive Gateway (Ingress Proxy Middleware)
- **Task:** Capture real-time quota consumption from model calls at zero additional network cost.
- **Operation:** The system opens an OpenAI-compatible reverse proxy on the local network (`http://localhost:port/v1/chat/completions`). The user's IDE (Cursor, Zed), CLI tools (OMP), or bots (n8n, Ayzek) route their requests through this gateway.
- **Captured Headers:**
  - `anthropic-ratelimit-unified-5h-utilization`, `anthropic-ratelimit-unified-5h-reset`
  - `x-codex-primary-used-percent`, `x-codex-primary-reset-after-seconds`
  - `x-ratelimit-remaining-tokens`, `x-ratelimit-remaining-requests`
- **Trigger Logic:** As soon as quota utilization of `%100` (or `%90+`) is observed in a response header, local state is updated immediately and the alert engine is triggered without waiting for the active cron cycle.

---

## 3. Consequences and Trade-offs

### Benefits (Pros)
- **Immediate Response:** The system is notified the second the user consumes quota; there is no 5-minute cron delay.
- **Static-State Accuracy:** Even during hours with no requests, the reset time (`resetsAt`) of 5-hour rolling windows counts down with full accuracy.
- **Zero Additional Cost:** The passive track incurs no additional API or token usage; it reads the headers of existing traffic.
- **Optionality (Modularity):** The passive gateway is not required; users who do not want to use the proxy can still perform basic balance/quota tracking with the Active Poller alone.

### Trade-offs / Costs

- Requires adding a proxy middleware layer to the architecture.
- Client (IDE, CLI) base URL settings must be pointed to the local proxy (to fully benefit from the passive track).

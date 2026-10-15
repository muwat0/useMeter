# ADR-0005: Non-Destructive Stale and Degraded Usage State Management

- **Status:** Accepted
- **Date:** 2026-09-15
- **Decision Makers:** Murat
- **Related Documents:** [CONTEXT.md](../../CONTEXT.md), [docs/SPEC.md](../SPEC.md), [ADR-0001](0001-self-hosted-bff-architecture.md), [ADR-0002](0002-dual-engine-tracking-model.md), [ADR-0003](0003-multi-tenant-session-authentication.md), [ADR-0004](0004-security-perimeter-and-invitation-onboarding.md)

---

## 1. Context and Problem Statement

useMeter is a system that monitors quota and balance status across multiple AI providers (Anthropic, OpenAI, Google Cloud, DeepSeek, Cursor, etc.) in real time and periodically for developers and teams.

In the previous architecture, when a periodic or manual poll (`fetchUsage`) failed due to a network interruption, provider API timeout, HTTP 5xx error, or rate limit (`HTTP 429`), the system produced a **destructive** error report:
1. **Data Loss and Blind Spot:** Existing quota limits (`limits: []`) were completely deleted or reset. During a temporary 30-second network outage at the provider, users could not see previously known quotas (75% utilization, remaining balance, etc.) and encountered empty/erroneous cards on the dashboard.
2. **Conceptual Confusion (Quota Exhaustion vs. Communication Error):** An official provider response saying “your quota is exhausted” (100% exhaustion) was conflated on the same red error card with being unable to reach the provider server (DNS/timeout/502); telemetry health and actual usage exhaustion could not be distinguished.
3. **Loss of User Trust:** The interface suddenly turning red and data disappearing during a temporary network fluctuation gave the impression that the system was constantly crashing.

This situation required a robust state machine that preserves the last successful telemetry and clearly labels it in the interface as “stale/cached data.”

---

## 2. Alternatives Considered

### Alternative A: Return Only an Empty Report on Error (Previous Destructive Approach)
- **Rationale:** The simplest behavior at the time of an error is to treat the last data as unreliable and show no limits on the dashboard.
- **Reasons for Rejection:**
  - Temporary 500/503 responses or network timeouts from providers are common. Quota bars disappearing on every transient error degrades the user experience.
  - Reset counters (`resetsAt`) for hourly/daily quota windows disappear from the dashboard; users cannot see when quota will become available again.

### Alternative B: Silently Swallow the Error and Produce No Report
- **Rationale:** If polling fails, the last valid state remains in the database as is, and no new snapshot is written.
- **Reasons for Rejection:**
  - Users cannot tell that there is a problem with the provider (for example, that the API key has been revoked or the provider is down).
  - It is impossible to know how long the data has gone without being updated; the system falls into a “false healthy” state.

### Alternative C: Three-State Health Model and Non-Destructive Preservation of the Last Good State (Selected)
- **Rationale:** On a failed poll, the previous successful limits (`lastGood`) are preserved, but the report is explicitly marked as `health: "stale"`, `stale: true`, `source: "stale"`. The error message and last successful timestamp (`lastGoodFetchedAt`) are retained.
- **Result:** Users can continue to see their quotas and understand, through an amber warning, that the data is cached rather than current, along with the transient error behind it.

---

## 3. Decisions

### 1. Distinct Health Taxonomy (`UsageReportHealth` and `UsageReportSource`)
Explicit and unambiguous states have been added to the `src/types.ts` contract:
- `UsageReportHealth`: `"healthy" | "stale" | "error"`
- `UsageReportSource`: `"live" | "stale" | "error"`

```typescript
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
```

### 2. Four-State State Machine (State Machine Transitions)
The poller layer (`PollerEngine`) tracks the last successful report for each credential within tenant isolation (`ownerId` + `credentialId`):

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                             INITIAL                                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                    Initial Poll    │
             ┌───────────────────────┴───────────────────────┐
             │ Successful                                    │ Failed
             ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│        HEALTHY          │                     │          ERROR          │
│ source: "live"          │                     │ source: "error"         │
│ stale: false            │                     │ stale: false            │
│ limits: [current data]  │                     │ limits: []              │
│ lastGoodFetchedAt: t1   │                     │ lastGoodFetchedAt: none │
│ error: undefined        │                     │ error: "error details"  │
└────────────┬────────────┘                     └────────────┬────────────┘
             │                                               │
             │ Poll Error                                    │ Successful Poll
             ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│         STALE           │ ◄── Poll Error      │        HEALTHY          │
│ source: "stale"         │ ─────────────────── │ (Returns to healthy)    │
│ stale: true             │                     └─────────────────────────┘
│ limits: [t1 limits]     │                                  ▲
│ lastGoodFetchedAt: t1   │                                  │
│ error: "new error"      │ ─────────────────────────────────┘
└─────────────────────────┘         Successful Poll Again
```

1. **First Successful Poll (`healthy`):** The report is produced with `health: "healthy"`, `stale: false`, `source: "live"`, `lastGoodFetchedAt: fetchedAt`, and the last good state (`lastGood`) is updated.
2. **Subsequent Network / Provider Error (`stale`):** If a valid `lastGood` exists, the limits are not deleted (`limits = lastGood.limits`). The report is marked with `health: "stale"`, `stale: true`, `source: "stale"`, `lastGoodFetchedAt: lastGood.fetchedAt`; the active error message is written to the `error` field.
3. **Error on First Attempt (`error`):** If no telemetry has previously been recorded successfully, there are no limits to preserve, so the report has `health: "error"`, `stale: false`, `source: "error"`, `limits: []`.
4. **Error Recovery (Self-Healing):** When the next poll succeeds, the system returns directly to `healthy`; the `stale` flag becomes `false` and `error` is cleared.

### 3. Clear Distinction Between Provider Quota Exhaustion and Communication Errors
- **Quota Exhaustion (Exhaustion):** The provider API responded successfully (HTTP 200) and reported that the quota is exhausted (`usedFraction >= 1.0` or `status: "exhausted"`). This is NOT a polling error; from a telemetry perspective, it is **`health: "healthy"`** and live data. The card renders normally, with the quota bar shown as full.
- **Polling Error (Transport / API Failure):** Network timeout, HTTP 500/502/503/504, or invalid JSON responses are telemetry failures; they trigger the `stale` or `error` flow.

### 4. Database and Tenant Isolation (Storage Vault)
- `StorageVault` preserves the `health`, `stale`, `lastGoodFetchedAt`, `source`, and `error` fields at the SQLite JSON/column level when saving snapshots and in `getLatestUsage` calls.
- Resolution of the last good report is always scoped to the same `ownerId` and `credentialId`; data from different users or accounts is never mixed.

### 5. User Interface Presentation (UI Contract)
- **Healthy (`healthy`):** Normal card appearance. Live green indicators.
- **Stale / Preserved (`stale`):**
  - An amber warning badge and error text at the top of the card.
  - “Cached data — Last successful: DD.MM.YYYY HH:mm” information banner.
  - Existing limits, bars, and reset counters (`resetsAt`) continue to be displayed completely and interactively.
- **Initial Error (`error`):** Red error band, empty limits area, and an explanation of the provider connection error.

### 6. Security Boundary: Raw Response Isolation (No Raw Payload Exposure)
- Raw error stacks (stack traces), authorization headers, or raw HTTP response bodies returned by upstream providers are NEVER stored in snapshots or exposed in reports returned to the client. Only sanitized domain error messages are carried.


---

## 4. Trade-offs and Consequences

| Approach | Advantage | Trade-off / Risk | Mitigation |
|---|---|---|---|
| **Preserve Last Good (`stale`)** | Prevents quotas from disappearing from the screen during network outages; reset counters remain visible. | Users may mistake the displayed quota for current data and spend accordingly. | A prominent amber warning and “Last successful update” timestamp are placed on the card. |
| **Distinct Health Classification** | Actual quota exhaustion and infrastructure failures are not conflated. | Additional fields (`health`, `source`, `stale`, `lastGoodFetchedAt`) must be managed in the type system and interface. | Standardized with strict TypeScript types under `src/types.ts`. |
| **In-Memory + Database Fallback** | Recovery from the last successful snapshot in the database is possible even if the poller restarts. | Deserialization cost of the old snapshot. | Runs only on error and per individual account; the overhead is negligible. |
| **Raw Data Isolation** | The risk of API key or sensitive provider data leakage is eliminated. | Detailed raw provider error bodies are not directly visible in the frontend. | Errors are categorized server-side and localized into user-friendly messages. |

---

## 5. Verification and Acceptance Criteria

1. **Unit and Integration Tests:** The test suite (`tests/poller.test.ts`, `tests/storage.test.ts`, `tests/server.test.ts`) verifies non-destructive stale flows, initial error states, self-healing transitions, and tenant isolation.
2. **Interface Check:** The amber badge, last update date, and preserved quota bars were observed in the SSR render and client-side card rendering layers.
3. **Documentation Consistency:** `CONTEXT.md`, `docs/SPEC.md`, and `AGENTS.md` have been updated to fully align with this decision.

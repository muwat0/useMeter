import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageAmount, UsageLimit, UsageReport, UsageStatus, UsageWindow } from "../../types";

const UMANS_PROVIDER = "umans";
const DEFAULT_ENDPOINT = "https://api.code.umans.ai";
const USAGE_PATH = "/v1/usage";
const HOUR_MS = 3_600_000;

interface UmansPlan {
  display_name?: unknown;
}

interface UmansRequestsLimits {
  limit?: unknown;
  hard_cap?: unknown;
  window_seconds?: unknown;
}

interface UmansConcurrencyLimits {
  limit?: unknown;
  hard_cap?: unknown;
}

interface UmansLimits {
  requests?: UmansRequestsLimits;
  concurrency?: UmansConcurrencyLimits;
}

interface UmansWindow {
  started_at?: unknown;
  resets_at?: unknown;
  remaining_minutes?: unknown;
}

interface UmansPriority {
  low?: unknown;
}

interface UmansUsage {
  requests_in_window?: unknown;
  remaining_requests?: unknown;
  weighted_in_window?: unknown;
  weighted_remaining_requests?: unknown;
  concurrent_sessions?: unknown;
  tokens_in?: unknown;
  tokens_out?: unknown;
  priority?: UmansPriority;
}

interface UmansPayload {
  plan?: UmansPlan;
  limits?: UmansLimits;
  window?: UmansWindow;
  usage?: UmansUsage;
}

interface ApiErrorMessage {
  message?: unknown;
  error?: {
    message?: unknown;
  };
}

function toFiniteNumber(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return value;
}

function normalizeBaseUrl(baseUrl?: string): string {
  if (!baseUrl?.trim()) return DEFAULT_ENDPOINT;
  const trimmed = baseUrl.trim();
  const withoutTrailingSlash = trimmed.replace(/\/+$/, "");
  return withoutTrailingSlash.replace(/\/v1$/i, "") || DEFAULT_ENDPOINT;
}

function resolveStatus(usedFraction: number | undefined): UsageStatus {
  if (usedFraction === undefined) return "unknown";
  if (usedFraction >= 1) return "exhausted";
  if (usedFraction >= 0.9) return "warning";
  return "ok";
}

function softCapStatus(usedFraction: number | undefined): UsageStatus {
  if (usedFraction === undefined) return "unknown";
  if (usedFraction >= 0.9) return "warning";
  return "ok";
}

function buildAmount(args: {
  used: number | undefined;
  limit: number | undefined;
  remaining: number | undefined;
  unit: UsageAmount["unit"];
}): UsageAmount {
  const used = args.used;
  const limit = args.limit;
  const usedFraction = used !== undefined && limit !== undefined && limit > 0 ? Math.min(used / limit, 1) : undefined;
  return {
    used,
    limit,
    remaining: args.remaining,
    usedFraction,
    unit: args.unit,
  };
}

interface UmansParsedPayload {
  planName?: string;
  requestsLimit?: number;
  requestsHardCap?: number;
  requestsWindowSeconds?: number;
  concurrencyLimit?: number;
  resetsAtMs?: number;
  requestsInWindow?: number;
  remainingRequests?: number;
  weightedInWindow?: number;
  weightedRemainingRequests?: number;
  concurrentSessions?: number;
  lowPriority?: boolean;
}

function parseUmansPayload(json: unknown): UmansParsedPayload {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return {};
  }

  const payload = json as UmansPayload;
  const result: UmansParsedPayload = {};

  if (typeof payload.plan?.display_name === "string") {
    result.planName = payload.plan.display_name;
  }

  if (payload.limits) {
    if (payload.limits.requests) {
      result.requestsLimit = toFiniteNumber(payload.limits.requests.limit);
      result.requestsHardCap = toFiniteNumber(payload.limits.requests.hard_cap);
      result.requestsWindowSeconds = toFiniteNumber(payload.limits.requests.window_seconds);
    }
    if (payload.limits.concurrency) {
      result.concurrencyLimit = toFiniteNumber(payload.limits.concurrency.limit);
    }
  }

  if (typeof payload.window?.resets_at === "string") {
    const parsed = Date.parse(payload.window.resets_at);
    if (!Number.isNaN(parsed)) {
      result.resetsAtMs = parsed;
    }
  }

  if (payload.usage) {
    result.requestsInWindow = toFiniteNumber(payload.usage.requests_in_window);
    result.remainingRequests = toFiniteNumber(payload.usage.remaining_requests);
    result.weightedInWindow = toFiniteNumber(payload.usage.weighted_in_window);
    result.weightedRemainingRequests = toFiniteNumber(payload.usage.weighted_remaining_requests);
    result.concurrentSessions = toFiniteNumber(payload.usage.concurrent_sessions);
    if (typeof payload.usage.priority?.low === "boolean") {
      result.lowPriority = payload.usage.priority.low;
    }
  }

  return result;
}

function buildRequestsLimits(parsed: UmansParsedPayload): UsageLimit[] {
  const limit = parsed.requestsLimit;
  const hardCap = parsed.requestsHardCap;
  const rawUsed = parsed.requestsInWindow;
  const rawRemaining = parsed.remainingRequests;
  const weightedUsed = parsed.weightedInWindow;
  const weightedRemaining = parsed.weightedRemainingRequests;

  if (limit === undefined && rawUsed === undefined && weightedUsed === undefined) {
    return [];
  }

  const durationMs = parsed.requestsWindowSeconds ? parsed.requestsWindowSeconds * 1000 : 5 * HOUR_MS;
  const window: UsageWindow = {
    id: "5h",
    label: "Rolling 5h",
    durationMs,
    ...(parsed.resetsAtMs !== undefined ? { resetsAt: parsed.resetsAtMs, resetLabel: "tick" } : {}),
  };

  if (weightedUsed === undefined || hardCap === undefined) {
    const amount = buildAmount({
      used: weightedUsed ?? rawUsed,
      limit,
      remaining: weightedUsed !== undefined ? weightedRemaining : rawRemaining,
      unit: "requests",
    });
    return [
      {
        id: "umans_requests",
        label: "İstekler (Kayan 5h)",
        window,
        amount,
        status: resolveStatus(amount.usedFraction),
      },
    ];
  }

  const softAmount = buildAmount({
    used: weightedUsed,
    limit,
    remaining: weightedRemaining,
    unit: "requests",
  });
  const limits: UsageLimit[] = [
    {
      id: "umans_requests_soft",
      label: "İstekler (Esnek Limit)",
      window,
      amount: softAmount,
      status: softCapStatus(softAmount.usedFraction),
    },
  ];

  if (hardCap !== undefined && rawUsed !== undefined) {
    const hardAmount = buildAmount({
      used: rawUsed,
      limit: hardCap,
      remaining: Math.max(0, hardCap - rawUsed),
      unit: "requests",
    });
    limits.push({
      id: "umans_requests_hard",
      label: "İstekler (Tepe Sınır)",
      window,
      amount: hardAmount,
      status: resolveStatus(hardAmount.usedFraction),
    });
  }

  return limits;
}

function buildConcurrencyLimit(parsed: UmansParsedPayload): UsageLimit | null {
  const limit = parsed.concurrencyLimit;
  const used = parsed.concurrentSessions;
  if (limit === undefined && used === undefined) return null;

  const remaining = limit !== undefined && used !== undefined ? Math.max(0, limit - used) : undefined;
  const amount = buildAmount({
    used,
    limit,
    remaining,
    unit: "requests",
  });

  return {
    id: "umans_concurrency",
    label: "Eşzamanlı Oturum",
    amount,
    status: resolveStatus(amount.usedFraction),
  };
}

export class UmansAdapter implements ProviderAdapter {
  readonly id = UMANS_PROVIDER;

  supports(provider: string): boolean {
    return provider.toLowerCase() === UMANS_PROVIDER;
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const token = credential.secret?.trim();
    if (!token) {
      throw new Error("Umans credential secret (API key) is missing or empty.");
    }

    const fetchImpl = ctx?.fetch ?? fetch;
    const rawBaseUrl = credential.metadata?.["baseUrl"];
    const baseUrlMetadata = typeof rawBaseUrl === "string" ? rawBaseUrl : undefined;
    const baseUrl = normalizeBaseUrl(baseUrlMetadata);
    const url = `${baseUrl}${USAGE_PATH}`;

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "User-Agent": "Usage-Dashboard/1.0",
    };

    const response = await fetchImpl(url, {
      method: "GET",
      headers,
      signal: ctx?.signal,
    });

    if (!response.ok) {
      let errorDetail = "";
      try {
        const errJson = (await response.json()) as ApiErrorMessage;
        if (typeof errJson.message === "string") {
          errorDetail = `: ${errJson.message}`;
        } else if (typeof errJson.error?.message === "string") {
          errorDetail = `: ${errJson.error.message}`;
        }
      } catch {
        // Body was not JSON; ignore detail extraction
      }
      throw new Error(`Umans API HTTP ${response.status} (${response.statusText})${errorDetail}`);
    }

    let payloadJson: unknown;
    try {
      payloadJson = await response.json();
    } catch {
      throw new Error("Umans usage response was not valid JSON.");
    }

    if (typeof payloadJson !== "object" || payloadJson === null || Array.isArray(payloadJson)) {
      throw new Error("Umans usage response was not a JSON object.");
    }

    const parsed = parseUmansPayload(payloadJson);
    const limits: UsageLimit[] = [...buildRequestsLimits(parsed)];

    const concurrency = buildConcurrencyLimit(parsed);
    if (concurrency) {
      limits.push(concurrency);
    }
    if (limits.length > 0 && parsed.lowPriority) {
      const firstLimit = limits[0];
      if (firstLimit) {
        firstLimit.notes = ["Hız sınırı aşımı sonrası istekler düşük önceliğe alındı."];
      }
    }
    return {
      provider: UMANS_PROVIDER,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits,
    };
  }
}

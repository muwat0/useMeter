import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus } from "../../types";

const PROVIDER = "cline-pass";
const CLINEPASS_API_BASE_URL = "https://api.cline.bot/api/v1";
const USAGE_LIMITS_PATH = "/users/me/plan/usage-limits";

const WINDOW_CONFIG = {
  five_hour: { id: "cline-pass-5h", windowId: "5h", label: "5-Hour Rolling Window", durationMs: 5 * 60 * 60 * 1_000 },
  weekly: { id: "cline-pass-weekly", windowId: "7d", label: "Weekly Window", durationMs: 7 * 24 * 60 * 60 * 1_000 },
  monthly: { id: "cline-pass-monthly", windowId: "30d", label: "Monthly Window", durationMs: 30 * 24 * 60 * 60 * 1_000 },
} as const;

type WindowType = keyof typeof WINDOW_CONFIG;

interface RawClineLimit {
  type?: unknown;
  percentUsed?: unknown;
  resetsAt?: unknown;
}

interface RawClineResponse {
  data?: {
    limits?: unknown;
  };
  limits?: unknown;
}

interface RawErrorResponse {
  message?: unknown;
  error?: unknown;
}

interface RawSecretJson {
  apiKey?: unknown;
  token?: unknown;
  secret?: unknown;
}

function parseLimit(raw: unknown): UsageLimit | null {
  if (typeof raw !== "object" || raw === null) {
    return null;
  }

  const item = raw as RawClineLimit;
  if (typeof item.type !== "string" || !(item.type in WINDOW_CONFIG)) {
    return null;
  }
  if (typeof item.percentUsed !== "number" || !Number.isFinite(item.percentUsed)) {
    return null;
  }

  const config = WINDOW_CONFIG[item.type as WindowType];
  const used = Math.max(0, item.percentUsed);
  const usedFraction = used / 100;

  let resetsAt: number | undefined;
  if (typeof item.resetsAt === "string") {
    const timestamp = Date.parse(item.resetsAt);
    if (Number.isFinite(timestamp)) {
      resetsAt = timestamp;
    }
  }

  const status: UsageStatus = usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok";

  return {
    id: config.id,
    label: config.label,
    amount: {
      used,
      limit: 100,
      remaining: Math.max(0, 100 - used),
      usedFraction,
      unit: "percent",
    },
    window: {
      id: config.windowId,
      label: config.label,
      durationMs: config.durationMs,
      ...(resetsAt !== undefined ? { resetsAt } : {}),
    },
    status,
  };
}

function extractApiKey(secret: string): string {
  const trimmed = secret.trim();
  if (!trimmed) {
    throw new Error("ClinePass API key is missing");
  }
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (typeof parsed === "object" && parsed !== null) {
        const json = parsed as RawSecretJson;
        if (typeof json.apiKey === "string" && json.apiKey.trim()) {
          return json.apiKey.trim();
        }
        if (typeof json.token === "string" && json.token.trim()) {
          return json.token.trim();
        }
        if (typeof json.secret === "string" && json.secret.trim()) {
          return json.secret.trim();
        }
      }
    } catch {
      // not JSON, fallback to raw string
    }
  }
  return trimmed;
}

export class ClinePassAdapter implements ProviderAdapter {
  readonly id = PROVIDER;

  supports(provider: string): boolean {
    const normalized = provider.trim().toLowerCase();
    return normalized === "cline-pass" || normalized === "clinepass";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const apiKey = extractApiKey(credential.secret);
    const usageUrl = `${CLINEPASS_API_BASE_URL}${USAGE_LIMITS_PATH}`;

    const response = await fetchImpl(usageUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${apiKey}`,
        "HTTP-Referer": "https://cline.bot",
        "X-Title": "Cline",
        "X-IS-MULTIROOT": "false",
        "X-CLIENT-TYPE": "cline-sdk",
        "User-Agent": "Cline/3.0.58",
        "X-CLIENT-VERSION": "3.0.58",
        "X-PLATFORM": process.platform,
        "X-PLATFORM-VERSION": "3.0.54",
        "X-CORE-VERSION": "0.0.79",
      },
      signal: ctx?.signal,
    });

    if (!response.ok) {
      let errorDetail = "";
      try {
        const errorBody: unknown = await response.json();
        if (typeof errorBody === "object" && errorBody !== null) {
          const errObj = errorBody as RawErrorResponse;
          if (typeof errObj.message === "string" && errObj.message.trim()) {
            errorDetail = `: ${errObj.message.trim()}`;
          } else if (typeof errObj.error === "string" && errObj.error.trim()) {
            errorDetail = `: ${errObj.error.trim()}`;
          }
        }
      } catch {
        // body could not be parsed as JSON
      }

      throw new Error(`ClinePass usage query failed with HTTP ${response.status} ${response.statusText}${errorDetail}`);
    }

    const payload: unknown = await response.json();
    if (typeof payload !== "object" || payload === null) {
      throw new Error("ClinePass usage query returned invalid payload format");
    }

    const resp = payload as RawClineResponse;
    const limitsCandidate = Array.isArray(resp.limits) ? resp.limits : Array.isArray(resp.data?.limits) ? resp.data.limits : null;

    if (!limitsCandidate) {
      throw new Error("ClinePass usage query returned payload without limits list");
    }

    const limits: UsageLimit[] = [];
    for (const item of limitsCandidate) {
      const parsed = parseLimit(item);
      if (parsed) {
        limits.push(parsed);
      }
    }

    return {
      provider: PROVIDER,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits,
    };
  }
}

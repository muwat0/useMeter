import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus } from "../../types";

const OPENCODE_GO_PROVIDER = "opencode-go";
const DEFAULT_USAGE_URL = "https://opencode.ai/zen/go/v1/usage";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const OPENCODE_GO_WINDOWS = [
  { key: "rolling", limitId: "opencode-go-5h", windowId: "5h", label: "5 Hour", durationMs: 5 * HOUR_MS },
  { key: "weekly", limitId: "opencode-go-weekly", windowId: "7d", label: "Weekly", durationMs: 7 * DAY_MS },
  { key: "monthly", limitId: "opencode-go-monthly", windowId: "monthly", label: "Monthly", durationMs: undefined },
] as const;

function resolveStatus(windowStatus: unknown, usedFraction: number): UsageStatus {
  if (windowStatus === "rate-limited" || usedFraction >= 1) {
    return "exhausted";
  }
  if (usedFraction >= 0.8) {
    return "warning";
  }
  return "ok";
}

function buildWindowLimit(
  descriptor: (typeof OPENCODE_GO_WINDOWS)[number],
  payload: unknown,
): UsageLimit | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }

  const rawPercent = "percent" in payload ? payload.percent : undefined;
  const rawStatus = "status" in payload ? payload.status : undefined;

  if (
    typeof rawPercent !== "number" ||
    !Number.isFinite(rawPercent) ||
    rawPercent < 0 ||
    rawPercent > 100 ||
    (rawStatus !== "ok" && rawStatus !== "rate-limited")
  ) {
    return undefined;
  }

  const rawResetsAt = "resetsAt" in payload ? payload.resetsAt : undefined;
  const resetsAtMs = typeof rawResetsAt === "string" ? Date.parse(rawResetsAt) : Number.NaN;
  if (!Number.isFinite(resetsAtMs)) {
    return undefined;
  }

  const usedFraction = rawPercent / 100;

  return {
    id: descriptor.limitId,
    label: `${descriptor.label} Limit`,
    amount: {
      used: rawPercent,
      limit: 100,
      remaining: Math.max(0, 100 - rawPercent),
      usedFraction,
      unit: "percent",
    },
    window: {
      id: descriptor.windowId,
      label: descriptor.label,
      resetsAt: resetsAtMs,
      durationMs: descriptor.durationMs,
    },
    status: resolveStatus(rawStatus, usedFraction),
  };
}

export class OpenCodeGoAdapter implements ProviderAdapter {
  readonly id = OPENCODE_GO_PROVIDER;

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === OPENCODE_GO_PROVIDER || p === "opencode_go" || p === "opencode";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    if (credential.credentialType === "oauth") {
      throw new Error("OpenCode Go API key kimlik doğrulaması gerektirir; OAuth desteklenmez.");
    }

    const apiKey = credential.secret?.trim();
    if (!apiKey) {
      throw new Error("OpenCode Go API anahtarı boş olamaz.");
    }

    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();

    const response = await fetchImpl(DEFAULT_USAGE_URL, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      signal: ctx?.signal,
    });

    if (!response.ok) {
      let detail: string | undefined;
      try {
        const errorBody: unknown = await response.json();
        if (errorBody && typeof errorBody === "object" && "error" in errorBody) {
          const errObj = errorBody.error;
          if (errObj && typeof errObj === "object" && "message" in errObj && typeof errObj.message === "string") {
            detail = errObj.message;
          }
        }
      } catch {
        // Response body was not JSON
      }

      if (response.status === 403) {
        throw new Error(
          `OpenCode Go aboneliği aktif değil veya süresi dolmuş (HTTP 403)${detail ? `: ${detail}` : ""}`,
        );
      }

      if (response.status === 401) {
        throw new Error(
          `OpenCode Go API anahtarı geçersiz veya yetkisiz (HTTP 401)${detail ? `: ${detail}` : ""}`,
        );
      }

      throw new Error(
        `OpenCode Go kullanım sorgusu başarısız: HTTP ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ""}`,
      );
    }

    let rawPayload: unknown;
    try {
      rawPayload = await response.json();
    } catch {
      throw new Error("OpenCode Go yanıtı geçerli JSON formatında değil.");
    }

    if (!rawPayload || typeof rawPayload !== "object" || !("usage" in rawPayload)) {
      throw new Error("OpenCode Go kullanım yanıtında geçerli 'usage' nesnesi bulunamadı.");
    }

    const usageObj = rawPayload.usage;
    if (!usageObj || typeof usageObj !== "object" || Array.isArray(usageObj)) {
      throw new Error("OpenCode Go kullanım yanıtında 'usage' alanı bir nesne değil.");
    }

    const limits: UsageLimit[] = [];

    for (const descriptor of OPENCODE_GO_WINDOWS) {
      const windowValue = descriptor.key in usageObj ? (usageObj as Record<string, unknown>)[descriptor.key] : undefined;
      const limit = buildWindowLimit(descriptor, windowValue);
      if (limit) {
        limits.push(limit);
      }
    }

    if (limits.length === 0) {
      throw new Error("OpenCode Go kullanım verisinde geçerli kota penceresi ayrıştırılamadı.");
    }

    return {
      provider: OPENCODE_GO_PROVIDER,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

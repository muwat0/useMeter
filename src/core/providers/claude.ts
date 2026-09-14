import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface ClaudeUsageBucket {
  utilization?: number;
  resets_at?: string;
}

interface ClaudeUsageResponse {
  five_hour?: ClaudeUsageBucket | null;
  seven_day?: ClaudeUsageBucket | null;
  limits?: Array<{
    kind?: string;
    percent?: number;
    resets_at?: string | null;
    scope?: {
      model?: {
        display_name?: string | null;
      } | null;
    } | null;
  }> | null;
}

export class ClaudeAdapter implements ProviderAdapter {
  readonly id = "anthropic";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "anthropic" || p === "claude";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const response = await fetchImpl("https://api.anthropic.com/api/oauth/usage", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "User-Agent": "claude-cli/0.2.148 (external, cli)",
        Accept: "application/json",
        "anthropic-beta": "claude-code-20250219,oauth-2025-04-20",
      },
      signal: ctx?.signal,
    });

    if (!response.ok) {
      throw new Error(`Claude kullanım sorgusu başarısız: HTTP ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as ClaudeUsageResponse;

    // 5-Hour Rolling Window
    if (data.five_hour) {
      const utilPercent = typeof data.five_hour.utilization === "number" ? data.five_hour.utilization : 0;
      const resetsAt = data.five_hour.resets_at ? Date.parse(data.five_hour.resets_at) : undefined;
      const usedFraction = utilPercent / 100;

      limits.push({
        id: "5h",
        label: "5 Saatlik Kayan Kota",
        amount: {
          used: utilPercent,
          limit: 100,
          remaining: Math.max(0, 100 - utilPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "5h",
          label: "5 Saatlik Kayan Pencere",
          durationMs: 5 * 60 * 60 * 1000,
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    }

    // 7-Day Weekly Window
    if (data.seven_day) {
      const utilPercent = typeof data.seven_day.utilization === "number" ? data.seven_day.utilization : 0;
      const resetsAt = data.seven_day.resets_at ? Date.parse(data.seven_day.resets_at) : undefined;
      const usedFraction = utilPercent / 100;

      limits.push({
        id: "7d",
        label: "Haftalık Genel Kota",
        amount: {
          used: utilPercent,
          limit: 100,
          remaining: Math.max(0, 100 - utilPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "7d",
          label: "7 Günlük Pencere",
          durationMs: 7 * 24 * 60 * 60 * 1000,
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    }

    // Model-scoped limits (Opus, Sonnet, Fable)
    for (const item of data.limits ?? []) {
      const modelName = item.scope?.model?.display_name || item.kind || "Model";
      const utilPercent = typeof item.percent === "number" ? item.percent : 0;
      const resetsAt = item.resets_at ? Date.parse(item.resets_at) : undefined;
      const usedFraction = utilPercent / 100;

      limits.push({
        id: `weekly_${modelName.toLowerCase().replace(/\s+/g, "_")}`,
        label: `${modelName} Haftalık`,
        amount: {
          used: utilPercent,
          limit: 100,
          remaining: Math.max(0, 100 - utilPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "7d_model",
          label: `${modelName} Haftalık Pencere`,
          durationMs: 7 * 24 * 60 * 60 * 1000,
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    }

    return {
      provider: "anthropic",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
      raw: data,
    };
  }

  parseHeaders(headers: Headers, credential?: StoredCredential, now: number = Date.now()): UsageReport | null {
    const fiveHourUtil = headers.get("anthropic-ratelimit-unified-5h-utilization");
    const fiveHourReset = headers.get("anthropic-ratelimit-unified-5h-reset");

    if (!fiveHourUtil && !fiveHourReset) return null;

    const limits: UsageLimit[] = [];

    if (fiveHourUtil) {
      const usedFraction = parseFloat(fiveHourUtil);
      const resetSeconds = fiveHourReset ? parseFloat(fiveHourReset) : undefined;
      const resetsAt = resetSeconds && Number.isFinite(resetSeconds) ? resetSeconds * 1000 : undefined;
      const usedPercent = usedFraction * 100;

      limits.push({
        id: "5h",
        label: "5 Saatlik Kayan Kota (Header)",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: Math.max(0, 100 - usedPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "5h",
          label: "5 Saatlik Kayan Pencere",
          durationMs: 5 * 60 * 60 * 1000,
          resetsAt,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    }

    return {
      provider: "anthropic",
      credentialId: credential?.id,
      accountLabel: credential?.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

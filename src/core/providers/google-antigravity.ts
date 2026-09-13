import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface AntigravityQuotaInfo {
  remainingFraction?: number;
  resetTime?: string;
  windowId?: string;
  windowLabel?: string;
}

interface AntigravityModelInfo {
  displayName?: string;
  quotaInfo?: AntigravityQuotaInfo | AntigravityQuotaInfo[];
  quotaInfos?: AntigravityQuotaInfo[];
}

interface AntigravityUsageResponse {
  models?: Record<string, AntigravityModelInfo>;
}

export class GoogleAntigravityAdapter implements ProviderAdapter {
  readonly id = "google-antigravity";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "google-antigravity" || p === "google" || p === "gemini" || p === "antigravity";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const response = await fetchImpl("https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({}),
      signal: ctx?.signal,
    });

    if (!response.ok) {
      throw new Error(`Google Antigravity kota sorgusu başarısız: HTTP ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as AntigravityUsageResponse;
    const models = data.models ?? {};

    for (const [modelId, info] of Object.entries(models)) {
      const displayName = info.displayName || modelId;
      const rawQuotas = info.quotaInfo || info.quotaInfos || [];
      const quotas = Array.isArray(rawQuotas) ? rawQuotas : [rawQuotas];

      for (const q of quotas) {
        if (typeof q.remainingFraction !== "number") continue;

        const remainingFraction = Math.max(0, Math.min(1, q.remainingFraction));
        const usedFraction = Math.max(0, 1 - remainingFraction);
        const usedPercent = usedFraction * 100;
        const resetsAt = q.resetTime ? Date.parse(q.resetTime) : undefined;
        const windowLabel = q.windowLabel || (q.windowId?.includes("week") ? "Haftalık" : "Günlük");

        limits.push({
          id: `${modelId}_${q.windowId || "default"}`,
          label: `${displayName} (${windowLabel})`,
          amount: {
            used: usedPercent,
            limit: 100,
            remaining: remainingFraction * 100,
            usedFraction,
            unit: "percent",
          },
          window: {
            id: q.windowId || "window",
            resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
            resetLabel: "Yenilenme",
          },
          status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
        });
      }
    }

    return {
      provider: "google-antigravity",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
      raw: data,
    };
  }
}

import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface ZaiUsageLimitItem {
  type?: string;
  currentValue?: number;
  percentage?: number;
  remaining?: number;
  nextResetTime?: number;
}

interface ZaiQuotaPayload {
  data?: {
    limits?: ZaiUsageLimitItem[];
    level?: string;
  };
}

export class ZaiAdapter implements ProviderAdapter {
  readonly id = "zai";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "zai" || p === "zhipu" || p === "glm";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const res = await fetchImpl("https://api.z.ai/api/monitor/usage/quota/limit", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "User-Agent": "Zai-Client/1.0.0",
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (!res.ok) {
      throw new Error(`Zhipu ZAI kota sorgusu başarısız: HTTP ${res.status}`);
    }

    const data = (await res.json()) as ZaiQuotaPayload;
    const items = data.data?.limits || [];
    const level = data.data?.level ? `Plan: ${data.data.level}` : undefined;

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (!item) continue;
      const usedPercent = item.percentage ?? 0;
      const usedFraction = usedPercent / 100;
      const rawReset = item.nextResetTime;
      const resetsAt = typeof rawReset === "number" 
        ? (rawReset > 1_000_000_000_000 ? rawReset : rawReset * 1000)
        : undefined;

      limits.push({
        id: `zai_limit_${i}`,
        label: item.type ? `GLM ${item.type} Kotası` : "Zhipu GLM Kotası",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: Math.max(0, 100 - usedPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "window",
          label: "Dönem",
          resetsAt,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
        notes: level ? [level] : undefined,
      });
    }

    return {
      provider: "Zhipu AI (GLM)",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

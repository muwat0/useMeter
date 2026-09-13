import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface KimiLimitItem {
  name?: string;
  used?: number;
  total?: number;
  reset_time?: number | string;
}

interface KimiUsageResponse {
  limits?: KimiLimitItem[];
}

export class KimiAdapter implements ProviderAdapter {
  readonly id = "kimi";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "kimi" || p === "moonshot" || p === "kimi-code";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const res = await fetchImpl("https://api.kimi.com/coding/v1/usages", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (!res.ok) {
      throw new Error(`Kimi kullanım sorgusu başarısız: HTTP ${res.status}`);
    }

    const data = (await res.json()) as KimiUsageResponse;

    for (let i = 0; i < (data.limits || []).length; i++) {
      const item = data.limits?.[i];
      if (!item) continue;
      const total = item.total || 100;
      const used = item.used || 0;
      const remaining = Math.max(0, total - used);
      const usedPercent = total > 0 ? (used / total) * 100 : 0;

      let resetsAt: number | undefined;
      if (typeof item.reset_time === "number") {
        resetsAt = item.reset_time > 1_000_000_000_000 ? item.reset_time : item.reset_time * 1000;
      } else if (typeof item.reset_time === "string") {
        resetsAt = Date.parse(item.reset_time);
      }

      limits.push({
        id: `kimi_limit_${i}`,
        label: item.name ? `Kimi ${item.name}` : "Kimi Kodlama Kotası",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: 100 - usedPercent,
          usedFraction: usedPercent / 100,
          unit: "percent",
        },
        window: {
          id: "window",
          label: "Dönem",
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
          resetLabel: "Sıfırlanma",
        },
        status: remaining <= 0 ? "exhausted" : remaining <= 10 ? "warning" : "ok",
        notes: [`Kalan: ${remaining} / ${total}`],
      });
    }

    return {
      provider: "Moonshot Kimi",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

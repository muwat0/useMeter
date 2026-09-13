import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface XaiBillingResponse {
  creditUsagePercent?: number;
  currentPeriod?: {
    start?: string;
    end?: string;
    type?: string;
  };
}

export class XaiAdapter implements ProviderAdapter {
  readonly id = "xai-oauth";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "xai-oauth" || p === "xai" || p === "grok";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const res = await fetchImpl("https://cli-chat-proxy.grok.com/v1/billing?format=credits", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (!res.ok) {
      throw new Error(`xAI kullanım sorgusu başarısız: HTTP ${res.status}`);
    }

    const data = (await res.json()) as XaiBillingResponse;
    const usedPercent = typeof data.creditUsagePercent === "number" ? data.creditUsagePercent : 0;
    const usedFraction = usedPercent / 100;
    const resetsAt = data.currentPeriod?.end ? Date.parse(data.currentPeriod.end) : undefined;

    limits.push({
      id: "grok_credits",
      label: "xAI Grok Kullanım Kotası",
      amount: {
        used: usedPercent,
        limit: 100,
        remaining: Math.max(0, 100 - usedPercent),
        usedFraction,
        unit: "percent",
      },
      window: {
        id: "period",
        label: "Dönemsel Kota",
        resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
        resetLabel: "Sıfırlanma",
      },
      status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
    });

    return {
      provider: "xAI (Grok)",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

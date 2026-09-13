import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface CopilotQuotaDetail {
  entitlement?: number;
  overage_count?: number;
  percent_remaining?: number;
  quota_remaining?: number;
  unlimited?: boolean;
}

interface CopilotUsageResponse {
  copilot_plan?: string;
  quota_reset_date?: string;
  quota_snapshots?: {
    chat?: CopilotQuotaDetail;
    completions?: CopilotQuotaDetail;
    premium_interactions?: CopilotQuotaDetail;
  };
}

export class CopilotAdapter implements ProviderAdapter {
  readonly id = "github-copilot";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "github-copilot" || p === "copilot";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const res = await fetchImpl("https://api.github.com/copilot_internal/user", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "User-Agent": "GitHubCopilotChat/0.26.7",
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (!res.ok) {
      throw new Error(`Copilot kota sorgusu başarısız: HTTP ${res.status}`);
    }

    const data = (await res.json()) as CopilotUsageResponse;
    const resetsAt = data.quota_reset_date ? Date.parse(data.quota_reset_date) : undefined;
    const snapshots = data.quota_snapshots || {};

    // 1. Premium interactions (Claude 3.7 / o3-mini / GPT-4o)
    if (snapshots.premium_interactions) {
      const pi = snapshots.premium_interactions;
      const total = pi.entitlement || 200;
      const remaining = pi.quota_remaining ?? pi.entitlement ?? total;
      const used = Math.max(0, total - remaining);
      const usedPercent = total > 0 ? (used / total) * 100 : 0;

      limits.push({
        id: "premium_interactions",
        label: "Premium İstek Kotası (Claude 3.7 / o3-mini)",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: 100 - usedPercent,
          usedFraction: usedPercent / 100,
          unit: "percent",
        },
        window: {
          id: "monthly",
          label: "Aylık Yenilenme",
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
          resetLabel: "Sıfırlanma",
        },
        status: remaining <= 0 ? "exhausted" : remaining <= 20 ? "warning" : "ok",
        notes: [`Kalan: ${remaining} / ${total} istek`],
      });
    }

    // 2. Chat quota
    if (snapshots.chat) {
      const chat = snapshots.chat;
      const remainingPercent = chat.percent_remaining ?? 100;
      limits.push({
        id: "chat_quota",
        label: "Copilot Chat Kotası",
        amount: {
          used: 100 - remainingPercent,
          limit: 100,
          remaining: remainingPercent,
          usedFraction: (100 - remainingPercent) / 100,
          unit: "percent",
        },
        window: {
          id: "monthly",
          label: "Aylık Yenilenme",
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
        },
        status: remainingPercent <= 0 ? "exhausted" : "ok",
        notes: chat.unlimited ? ["Sınırsız Plan"] : undefined,
      });
    }

    return {
      provider: "GitHub Copilot",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

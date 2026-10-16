import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface OpenRouterKeyResponse {
  data?: {
    label?: string;
    usage?: number;
    limit?: number | null;
    limit_remaining?: number | null;
    is_free_tier?: boolean;
  };
}

interface OpenRouterCreditsResponse {
  data?: {
    total_credits?: number;
    total_usage?: number;
  };
}

export class OpenRouterAdapter implements ProviderAdapter {
  readonly id = "openrouter";

  supports(provider: string): boolean {
    return provider.toLowerCase() === "openrouter";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    // 1. Fetch Key details
    const keyRes = await fetchImpl("https://openrouter.ai/api/v1/auth/key", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "Content-Type": "application/json",
      },
      signal: ctx?.signal,
    });

    if (keyRes.ok) {
      const keyData = (await keyRes.json()) as OpenRouterKeyResponse;
      if (keyData.data) {
        const d = keyData.data;
        const used = typeof d.usage === "number" ? d.usage : 0;
        const limit = typeof d.limit === "number" ? d.limit : undefined;
        const remaining = typeof d.limit_remaining === "number" ? d.limit_remaining : undefined;

        limits.push({
          id: "key_usage",
          label: d.label ? `Anahtar: ${d.label}` : "API Anahtar Harcaması",
          amount: {
            used,
            limit,
            remaining,
            usedFraction: limit && limit > 0 ? used / limit : undefined,
            unit: "usd",
          },
          status: remaining !== undefined && remaining <= 0 ? "exhausted" : "ok",
          notes: d.is_free_tier ? ["Free tier hesabı"] : undefined,
        });

      }
    }

    // 2. Fetch Account Credits (if permitted)
    try {
      const credRes = await fetchImpl("https://openrouter.ai/api/v1/credits", {
        headers: {
          Authorization: `Bearer ${credential.secret}`,
          "Content-Type": "application/json",
        },
        signal: ctx?.signal,
      });

      if (credRes.ok) {
        const credData = (await credRes.json()) as OpenRouterCreditsResponse;
        if (credData.data) {
          const totalCredits = credData.data.total_credits ?? 0;
          const totalUsage = credData.data.total_usage ?? 0;
          const remainingCredits = Math.max(0, totalCredits - totalUsage);

          limits.unshift({
            id: "account_balance",
            label: "Hesap Net Bakiyesi",
            amount: {
              used: totalUsage,
              limit: totalCredits,
              remaining: remainingCredits,
              usedFraction: totalCredits > 0 ? totalUsage / totalCredits : undefined,
              unit: "usd",
            },
            status: remainingCredits <= 0 ? "exhausted" : remainingCredits < 2 ? "warning" : "ok",
            notes: [`Toplam Yüklenen: $${totalCredits.toFixed(2)}`, `Toplam Harcanan: $${totalUsage.toFixed(2)}`],
          });
        }
      }
    } catch (error) {
      if (ctx?.signal?.aborted) throw error;
    }

    return {
      provider: "openrouter",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

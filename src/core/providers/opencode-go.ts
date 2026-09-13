import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface OpenCodeWindowPayload {
  percent?: number;
  status?: string;
  resetsAt?: string;
}

interface OpenCodeGoResponse {
  rolling?: OpenCodeWindowPayload;
  weekly?: OpenCodeWindowPayload;
  monthly?: OpenCodeWindowPayload;
}

export class OpenCodeGoAdapter implements ProviderAdapter {
  readonly id = "opencode-go";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "opencode-go" || p === "opencode";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const res = await fetchImpl("https://opencode.ai/zen/go/v1/usage", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (!res.ok) {
      throw new Error(`OpenCode Go kullanım sorgusu başarısız: HTTP ${res.status}`);
    }

    const data = (await res.json()) as OpenCodeGoResponse;

    if (data.rolling) {
      const used = data.rolling.percent ?? 0;
      const resetsAt = data.rolling.resetsAt ? Date.parse(data.rolling.resetsAt) : undefined;
      limits.push({
        id: "rolling_5h",
        label: "5 Saatlik Kayan Limit",
        amount: { used, limit: 100, remaining: Math.max(0, 100 - used), usedFraction: used / 100, unit: "percent" },
        window: { id: "5h", label: "5 Saatlik", resetsAt, resetLabel: "Sıfırlanma" },
        status: used >= 100 ? "exhausted" : used >= 80 ? "warning" : "ok",
      });
    }

    if (data.weekly) {
      const used = data.weekly.percent ?? 0;
      const resetsAt = data.weekly.resetsAt ? Date.parse(data.weekly.resetsAt) : undefined;
      limits.push({
        id: "weekly",
        label: "Haftalık Limit",
        amount: { used, limit: 100, remaining: Math.max(0, 100 - used), usedFraction: used / 100, unit: "percent" },
        window: { id: "weekly", label: "Haftalık", resetsAt, resetLabel: "Sıfırlanma" },
        status: used >= 100 ? "exhausted" : used >= 80 ? "warning" : "ok",
      });
    }

    if (data.monthly) {
      const used = data.monthly.percent ?? 0;
      const resetsAt = data.monthly.resetsAt ? Date.parse(data.monthly.resetsAt) : undefined;
      limits.push({
        id: "monthly",
        label: "Aylık Limit",
        amount: { used, limit: 100, remaining: Math.max(0, 100 - used), usedFraction: used / 100, unit: "percent" },
        window: { id: "monthly", label: "Aylık", resetsAt, resetLabel: "Sıfırlanma" },
        status: used >= 100 ? "exhausted" : used >= 80 ? "warning" : "ok",
      });
    }

    return {
      provider: "OpenCode Go",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

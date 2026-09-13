import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface CursorModelUsage {
  numRequests?: number;
  numRequestsTotal?: number;
  maxRequestUsage?: number | null;
  maxTokenUsage?: number | null;
}

interface CursorUsageResponse {
  "gpt-4"?: CursorModelUsage;
  startOfMonth?: string;
  user?: {
    email?: string;
    membershipType?: string;
  };
}

export class CursorAdapter implements ProviderAdapter {
  readonly id = "cursor";

  supports(provider: string): boolean {
    return provider.toLowerCase() === "cursor";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const res = await fetchImpl("https://api2.cursor.sh/auth/usage", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "User-Agent": "Cursor/0.46.1",
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (!res.ok) {
      throw new Error(`Cursor kullanım sorgusu başarısız: HTTP ${res.status}`);
    }

    const data = (await res.json()) as CursorUsageResponse;
    const gpt4 = data["gpt-4"] || {};
    const used = gpt4.numRequests ?? 0;
    const maxReq = gpt4.maxRequestUsage ?? 500;
    const remaining = Math.max(0, maxReq - used);
    const usedFraction = maxReq > 0 ? used / maxReq : 0;

    // Reset date is typically 1st of next month
    let resetsAt: number | undefined;
    if (data.startOfMonth) {
      const start = new Date(data.startOfMonth);
      const nextMonth = new Date(start.getFullYear(), start.getMonth() + 1, 1);
      resetsAt = nextMonth.getTime();
    }

    limits.push({
      id: "fast_requests",
      label: "Cursor Hızlı İstek Kotası (Fast Requests)",
      amount: {
        used: (usedFraction * 100),
        limit: 100,
        remaining: (1 - usedFraction) * 100,
        usedFraction,
        unit: "percent",
      },
      window: {
        id: "monthly",
        label: "Aylık Yenilenme",
        resetsAt,
        resetLabel: "Sıfırlanma",
      },
      status: remaining <= 0 ? "exhausted" : remaining <= 50 ? "warning" : "ok",
      notes: [`Kullanılan: ${used} / ${maxReq} istek`],
    });

    return {
      provider: "Cursor",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

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

    // Auto-discover account email if label is still generic "Cursor" or "Default"
    let accountLabel = credential.accountLabel;
    const existingEmail = typeof credential.metadata?.["email"] === "string" ? (credential.metadata["email"] as string).trim() : undefined;
    if (existingEmail && (accountLabel === "Cursor" || accountLabel === "Default")) {
      accountLabel = existingEmail;
      if (ctx?.onTokenRefresh) {
        ctx.onTokenRefresh(credential.secret, credential.metadata, existingEmail);
      }
    } else if (accountLabel === "Cursor" || accountLabel === "Default" || !existingEmail) {
      try {
        const parts = credential.secret.split(".");
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { sub?: string; email?: string };
          let email = typeof payload.email === "string" && payload.email.trim() ? payload.email.trim() : undefined;
          if (!email && typeof payload.sub === "string") {
            const subParts = payload.sub.trim().split("|");
            const userId = subParts.length > 1 ? subParts[1] : payload.sub.trim();
            const meRes = await fetchImpl("https://cursor.com/api/auth/me", {
              headers: {
                Accept: "application/json",
                Cookie: `WorkosCursorSessionToken=${encodeURIComponent(`${userId}::${credential.secret}`)}`,
                "User-Agent": "Cursor/0.46.1",
              },
              signal: ctx?.signal,
            });
            if (meRes.ok) {
              const meJson = (await meRes.json()) as { email?: string };
              if (typeof meJson.email === "string" && meJson.email.trim()) {
                email = meJson.email.trim();
              }
            }
          }
          if (email) {
            accountLabel = email;
            credential.accountLabel = email;
            if (ctx?.onTokenRefresh) {
              ctx.onTokenRefresh(credential.secret, { ...(credential.metadata || {}), email }, email);
            }
          }
        }
      } catch (err) {
        if (ctx?.signal?.aborted) throw err;
      }
    }

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
      accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

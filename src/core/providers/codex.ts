import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface CodexUsageWindowPayload {
  used_percent?: number;
  limit_window_seconds?: number;
  reset_after_seconds?: number;
  reset_at?: number;
}

interface CodexUsageResponse {
  plan_type?: string;
  rate_limit?: {
    allowed?: boolean;
    limit_reached?: boolean;
    primary_window?: CodexUsageWindowPayload | null;
    secondary_window?: CodexUsageWindowPayload | null;
  } | null;
}

interface CodexResetCreditItem {
  id?: string;
  status?: string;
  expires_at?: string;
  title?: string;
  description?: string;
}

interface CodexResetCreditsResponse {
  credits?: CodexResetCreditItem[];
  available_count?: number;
}

export class CodexAdapter implements ProviderAdapter {
  readonly id = "openai-codex";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "openai-codex" || p === "codex" || p === "chatgpt";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const headers: Record<string, string> = {
      Authorization: `Bearer ${credential.secret}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "codex-cli/1.0.0",
    };

    const accountId = credential.metadata?.["accountId"];
    if (typeof accountId === "string" && accountId.trim()) {
      headers["chatgpt-account-id"] = accountId.trim();
    }

    const response = await fetchImpl("https://chatgpt.com/backend-api/wham/usage", {
      headers,
      signal: ctx?.signal,
    });

    if (!response.ok) {
      throw new Error(`Codex kullanım sorgusu başarısız: HTTP ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as CodexUsageResponse;
    const rateLimit = data.rate_limit;
    const plan = data.plan_type ? `Plan: ${data.plan_type}` : undefined;

    // Primary window (usually 5 hours)
    if (rateLimit?.primary_window) {
      const w = rateLimit.primary_window;
      const usedPercent = typeof w.used_percent === "number" ? w.used_percent : 0;
      const durationMs = (w.limit_window_seconds ?? 5 * 3600) * 1000;
      let resetsAt: number | undefined;

      if (typeof w.reset_at === "number") {
        resetsAt = w.reset_at < 1_000_000_000_000 ? w.reset_at * 1000 : w.reset_at;
      } else if (typeof w.reset_after_seconds === "number") {
        resetsAt = now + w.reset_after_seconds * 1000;
      }

      const usedFraction = usedPercent / 100;

      limits.push({
        id: "primary_window",
        label: "5 Saatlik Kayan Kota",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: Math.max(0, 100 - usedPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "primary",
          durationMs,
          resetsAt,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 || rateLimit.limit_reached ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
        notes: plan ? [plan] : undefined,
      });
    }

    // Secondary window (weekly / monthly)
    if (rateLimit?.secondary_window) {
      const w = rateLimit.secondary_window;
      const usedPercent = typeof w.used_percent === "number" ? w.used_percent : 0;
      const durationMs = (w.limit_window_seconds ?? 7 * 24 * 3600) * 1000;
      let resetsAt: number | undefined;

      if (typeof w.reset_at === "number") {
        resetsAt = w.reset_at < 1_000_000_000_000 ? w.reset_at * 1000 : w.reset_at;
      } else if (typeof w.reset_after_seconds === "number") {
        resetsAt = now + w.reset_after_seconds * 1000;
      }

      const usedFraction = usedPercent / 100;

      limits.push({
        id: "secondary_window",
        label: "Haftalık / Uzun Dönem Kotası",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: Math.max(0, 100 - usedPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "secondary",
          durationMs,
          resetsAt,
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    }

    // 3. Rate limit reset credits
    try {
      const resetRes = await fetchImpl("https://chatgpt.com/backend-api/wham/rate-limit-reset-credits", {
        headers,
        signal: ctx?.signal,
      });

      if (resetRes.ok) {
        const resetData = (await resetRes.json()) as CodexResetCreditsResponse;
        const count = typeof resetData.available_count === "number" ? resetData.available_count : 0;
        const availableCredits = (resetData.credits ?? []).filter(c => c.status === "available");
        const credit = availableCredits[0];

        const notes: string[] = [];
        if (credit?.title) notes.push(credit.title);
        if (credit?.expires_at) {
          const expDate = new Date(credit.expires_at);
          notes.push(`Son Geçerlilik: ${expDate.toLocaleDateString("tr-TR")}`);
        }

        limits.push({
          id: "reset_credits",
          label: "Kota Sıfırlama Hakkı (Usage Reset)",
          amount: {
            remaining: count,
            unit: "credits",
          },
          status: count > 0 ? "ok" : "exhausted",
          notes: notes.length > 0 ? notes : [`${count} adet kullanılabilir reset hakkı`],
        });
      }
    } catch {}
    return {
      provider: "openai-codex",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
      raw: data,
    };
  }

  parseHeaders(headers: Headers, credential?: StoredCredential, now: number = Date.now()): UsageReport | null {
    const primaryUsed = headers.get("x-codex-primary-used-percent");
    const primaryReset = headers.get("x-codex-primary-reset-after-seconds");

    if (!primaryUsed && !primaryReset) return null;

    const limits: UsageLimit[] = [];

    if (primaryUsed) {
      const usedPercent = parseFloat(primaryUsed);
      const usedFraction = usedPercent / 100;
      const resetSeconds = primaryReset ? parseFloat(primaryReset) : undefined;
      const resetsAt = resetSeconds && Number.isFinite(resetSeconds) ? now + resetSeconds * 1000 : undefined;

      limits.push({
        id: "primary_window",
        label: "5 Saatlik Kayan Kota (Header)",
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: Math.max(0, 100 - usedPercent),
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "primary",
          resetsAt,
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    }

    return {
      provider: "openai-codex",
      credentialId: credential?.id,
      accountLabel: credential?.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";
import { refreshXaiToken } from "../oauth/xai";

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

    const headers = {
      Authorization: `Bearer ${credential.secret}`,
      Accept: "application/json",
    };
    let res = await fetchImpl("https://cli-chat-proxy.grok.com/v1/billing?format=credits", {
      headers,
      signal: ctx?.signal,
    });

    const refreshToken = credential.metadata?.["refreshToken"];
    if (res.status === 401 && typeof refreshToken === "string" && refreshToken.trim()) {
      let refreshed: { accessToken: string; refreshToken: string };
      try {
        refreshed = await refreshXaiToken(refreshToken, { fetch: fetchImpl, signal: ctx?.signal });
      } catch (error) {
        if (ctx?.signal?.aborted) throw error;
        throw new Error("xAI usage returned HTTP 401; OAuth token refresh failed.");
      }

      const nextRefreshToken =
        typeof refreshed.refreshToken === "string" && refreshed.refreshToken.trim()
          ? refreshed.refreshToken
          : refreshToken;
      credential.secret = refreshed.accessToken;
      credential.metadata = { ...(credential.metadata ?? {}), refreshToken: nextRefreshToken };
      ctx?.onTokenRefresh?.(refreshed.accessToken, { refreshToken: nextRefreshToken });
      headers.Authorization = `Bearer ${refreshed.accessToken}`;
      res = await fetchImpl("https://cli-chat-proxy.grok.com/v1/billing?format=credits", {
        headers,
        signal: ctx?.signal,
      });
    }

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

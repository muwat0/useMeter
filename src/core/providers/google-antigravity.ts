import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

const CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const CLIENT_SECRET = "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";
const ANTIGRAVITY_USER_AGENT = "antigravity/hub/2.8.0 (aidev_client; os_type=darwin; arch=arm64; cl=963137146)";
const DEFAULT_ENDPOINT = "https://daily-cloudcode-pa.googleapis.com";

interface AntigravityQuotaInfo {
  remainingFraction?: number;
  resetTime?: string;
  windowId?: string;
  windowLabel?: string;
}

interface AntigravityModelInfo {
  displayName?: string;
  quotaInfo?: AntigravityQuotaInfo | AntigravityQuotaInfo[];
  quotaInfos?: AntigravityQuotaInfo[];
}

interface AntigravityUsageResponse {
  models?: Record<string, AntigravityModelInfo>;
}

export class GoogleAntigravityAdapter implements ProviderAdapter {
  readonly id = "google-antigravity";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "google-antigravity" || p === "google" || p === "gemini" || p === "antigravity";
  }

  async refreshAccessToken(refreshToken: string): Promise<string> {
    const res = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: "refresh_token",
      }).toString(),
    });

    if (!res.ok) {
      throw new Error(`Google token yenileme başarısız: HTTP ${res.status}`);
    }

    const json = (await res.json()) as { access_token?: string };
    if (!json.access_token) {
      throw new Error("Yenilenen access_token alınamadı.");
    }
    return json.access_token;
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    let accessToken = credential.secret;

    // 1. Auto-refresh access token if refreshToken is available
    const refreshToken = credential.metadata?.["refreshToken"] as string | undefined;
    if (refreshToken) {
      try {
        accessToken = await this.refreshAccessToken(refreshToken);
      } catch (err) {
        console.warn("[GoogleAntigravity] Token refresh fallback to current secret:", err);
      }
    }

    // 2. Discover or default project
    let projectId = (credential.metadata?.["projectId"] as string | undefined) || "aicode-consumers";
    try {
      const loadRes = await fetchImpl(`${DEFAULT_ENDPOINT}/v1internal:loadCodeAssist`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
          "User-Agent": ANTIGRAVITY_USER_AGENT,
        },
        body: JSON.stringify({ metadata: { ideType: "ANTIGRAVITY" } }),
        signal: ctx?.signal,
      });

      if (loadRes.ok) {
        const loadJson = (await loadRes.json()) as { cloudaicompanionProject?: string };
        if (loadJson.cloudaicompanionProject) {
          projectId = loadJson.cloudaicompanionProject;
        }
      }
    } catch {}

    // 3. Fetch available models with project and User-Agent
    const response = await fetchImpl(`${DEFAULT_ENDPOINT}/v1internal:fetchAvailableModels`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "User-Agent": ANTIGRAVITY_USER_AGENT,
      },
      body: JSON.stringify({ project: projectId }),
      signal: ctx?.signal,
    });

    if (!response.ok) {
      throw new Error(`Google Antigravity kota sorgusu başarısız: HTTP ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as AntigravityUsageResponse;
    const models = data.models ?? {};

    // 4. Group and deduplicate shared pools
    interface PoolBucket {
      name: string;
      remainingFraction: number;
      resetTime?: string;
      models: string[];
    }

    const pools = new Map<string, PoolBucket>();

    for (const [modelId, info] of Object.entries(models)) {
      const displayName = info.displayName || modelId;
      const rawQuotas = info.quotaInfo || info.quotaInfos || [];
      const quotas = Array.isArray(rawQuotas) ? rawQuotas : [rawQuotas];

      for (const q of quotas) {
        if (typeof q.remainingFraction !== "number") continue;

        let poolKey = "gemini";
        let poolName = "Google Gemini Havuzu (3 Flash / 2.5 Pro)";

        if (modelId.includes("claude")) {
          poolKey = "claude";
          poolName = "Claude Havuzu (Sonnet 4.6 / Opus 4.6)";
        } else if (modelId.includes("gpt-oss")) {
          poolKey = "gpt-oss";
          poolName = "GPT-OSS Havuzu (120B)";
        }

        const existing = pools.get(poolKey);
        if (!existing) {
          pools.set(poolKey, {
            name: poolName,
            remainingFraction: q.remainingFraction,
            resetTime: q.resetTime,
            models: [displayName],
          });
        } else {
          // Keep lowest remaining (strictest bound)
          if (q.remainingFraction < existing.remainingFraction) {
            existing.remainingFraction = q.remainingFraction;
          }
          if (!existing.resetTime && q.resetTime) {
            existing.resetTime = q.resetTime;
          }
          if (!existing.models.includes(displayName)) {
            existing.models.push(displayName);
          }
        }
      }
    }

    const limits: UsageLimit[] = [];

    for (const [poolKey, bucket] of pools.entries()) {
      const remainingFraction = Math.max(0, Math.min(1, bucket.remainingFraction));
      const usedFraction = Math.max(0, 1 - remainingFraction);
      const usedPercent = usedFraction * 100;
      const resetsAt = bucket.resetTime ? Date.parse(bucket.resetTime) : undefined;

      limits.push({
        id: `antigravity_${poolKey}`,
        label: bucket.name,
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: remainingFraction * 100,
          usedFraction,
          unit: "percent",
        },
        window: {
          id: "daily_window",
          resetsAt: Number.isFinite(resetsAt) ? resetsAt : undefined,
          resetLabel: "Yenilenme",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
        notes: [`Modeller: ${bucket.models.slice(0, 3).join(", ")}${bucket.models.length > 3 ? "..." : ""}`],
      });
    }

    return {
      provider: "google-antigravity",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
      raw: data,
    };
  }
}

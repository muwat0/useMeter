import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

const CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const CLIENT_SECRET = "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";
const ANTIGRAVITY_USER_AGENT = "antigravity/hub/2.8.0 (aidev_client; os_type=darwin; arch=arm64; cl=963137146)";
const DEFAULT_ENDPOINT = "https://daily-cloudcode-pa.googleapis.com";
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const FIVE_HOUR_MS = 5 * 60 * 60 * 1000;

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
  dailyQuotaInfo?: AntigravityQuotaInfo | AntigravityQuotaInfo[];
  weeklyQuotaInfo?: AntigravityQuotaInfo | AntigravityQuotaInfo[];
}

interface AntigravityUsageResponse {
  models?: Record<string, AntigravityModelInfo>;
}

export class GoogleAntigravityAdapter implements ProviderAdapter {
  readonly id = "antigravity";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "antigravity" || p === "google-antigravity" || p === "google" || p === "gemini";
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

    // 1. Auto-refresh access token if refreshToken is present
    const refreshToken = credential.metadata?.["refreshToken"] as string | undefined;
    if (refreshToken) {
      try {
        accessToken = await this.refreshAccessToken(refreshToken);
      } catch (err) {
        console.warn("[GoogleAntigravity] Token refresh fallback to current secret:", err);
      }
    }

    // 2. Discover project
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

    // 3. Fetch available models
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

    // 4. Scan counters for Gemini and Claude
    let geminiRollingRemaining = 1.0;
    let geminiRollingResetAt: number | undefined;
    let geminiWeeklyRemaining = 1.0;
    let geminiWeeklyResetAt: number | undefined;

    let claudeGptRollingRemaining = 1.0;
    let claudeGptRollingResetAt: number | undefined;
    let claudeGptWeeklyRemaining = 1.0;
    let claudeGptWeeklyResetAt: number | undefined;

    for (const [modelId, info] of Object.entries(models)) {
      const rawQuotas = [
        ...(Array.isArray(info.quotaInfo) ? info.quotaInfo : info.quotaInfo ? [info.quotaInfo] : []),
        ...(Array.isArray(info.quotaInfos) ? info.quotaInfos : info.quotaInfos ? [info.quotaInfos] : []),
        ...(Array.isArray(info.dailyQuotaInfo) ? info.dailyQuotaInfo : info.dailyQuotaInfo ? [info.dailyQuotaInfo] : []),
        ...(Array.isArray(info.weeklyQuotaInfo) ? info.weeklyQuotaInfo : info.weeklyQuotaInfo ? [info.weeklyQuotaInfo] : []),
      ];

      for (const q of rawQuotas) {
        if (typeof q.remainingFraction !== "number") continue;
        const resetAt = q.resetTime ? Date.parse(q.resetTime) : undefined;
        const isWeekly = q.windowId?.includes("week") || (resetAt && resetAt - now > 24 * 3600 * 1000);

        if (modelId.includes("claude") || modelId.includes("gpt-oss")) {
          // Claude and GPT models share a combined quota pool in Antigravity
          if (isWeekly) {
            if (q.remainingFraction < claudeGptWeeklyRemaining) claudeGptWeeklyRemaining = q.remainingFraction;
            if (resetAt && (!claudeGptWeeklyResetAt || resetAt > claudeGptWeeklyResetAt)) claudeGptWeeklyResetAt = resetAt;
          } else {
            if (q.remainingFraction < claudeGptRollingRemaining) claudeGptRollingRemaining = q.remainingFraction;
            if (resetAt && (!claudeGptRollingResetAt || resetAt < claudeGptRollingResetAt)) claudeGptRollingResetAt = resetAt;
          }
        } else if (!modelId.startsWith("tab_") && !modelId.startsWith("chat_")) {
          // Gemini models pool
          if (isWeekly) {
            if (q.remainingFraction < geminiWeeklyRemaining) geminiWeeklyRemaining = q.remainingFraction;
            if (resetAt && (!geminiWeeklyResetAt || resetAt > geminiWeeklyResetAt)) geminiWeeklyResetAt = resetAt;
          } else {
            if (q.remainingFraction < geminiRollingRemaining) geminiRollingRemaining = q.remainingFraction;
            if (resetAt && (!geminiRollingResetAt || resetAt < geminiRollingResetAt)) geminiRollingResetAt = resetAt;
          }
        }
      }
    }

    const limits: UsageLimit[] = [];

    // Helper to build clean limit entry with NO model notes
    const addLimit = (
      id: string,
      label: string,
      remainingFrac: number,
      windowId: string,
      durationMs: number,
      resetsAt?: number,
    ) => {
      const remainingFraction = Math.max(0, Math.min(1, remainingFrac));
      const usedFraction = Math.max(0, 1 - remainingFraction);
      const usedPercent = usedFraction * 100;

      limits.push({
        id,
        label,
        amount: {
          used: usedPercent,
          limit: 100,
          remaining: remainingFraction * 100,
          usedFraction,
          unit: "percent",
        },
        window: {
          id: windowId,
          label: windowId === "5h" ? "5 Saatlik Kayan Pencere" : "Haftalık Pencere",
          durationMs,
          resetsAt,
          resetLabel: "Sıfırlanma",
        },
        status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
      });
    };

    // 1. Gemini 5-Hour Limit
    addLimit(
      "gemini_5h",
      "Gemini: 5-Hour Limit",
      geminiRollingRemaining,
      "5h",
      FIVE_HOUR_MS,
      geminiRollingResetAt,
    );

    // 2. Gemini Weekly Limit
    const weeklyResetTime = geminiWeeklyResetAt || (geminiRollingResetAt ? geminiRollingResetAt + 6 * 24 * 3600 * 1000 : now + WEEK_MS);
    addLimit(
      "gemini_weekly",
      "Gemini: Weekly Limit",
      geminiWeeklyRemaining < 1 ? geminiWeeklyRemaining : Math.max(0.7, geminiRollingRemaining),
      "weekly",
      WEEK_MS,
      weeklyResetTime,
    );

    // 3. Claude & GPT 5-Hour Limit
    addLimit(
      "claude_gpt_5h",
      "Claude & GPT: 5-Hour Limit",
      claudeGptRollingRemaining,
      "5h",
      FIVE_HOUR_MS,
      claudeGptRollingResetAt,
    );

    // 4. Claude & GPT Weekly Limit
    const claudeGptWeeklyReset = claudeGptWeeklyResetAt || (claudeGptRollingResetAt ? claudeGptRollingResetAt + 6 * 24 * 3600 * 1000 : now + WEEK_MS);
    addLimit(
      "claude_gpt_weekly",
      "Claude & GPT: Weekly Limit",
      claudeGptWeeklyRemaining,
      "weekly",
      WEEK_MS,
      claudeGptWeeklyReset,
    );

    const cleanLabel = credential.accountLabel.replace(/^Google \((.*)\)$/, "$1");

    return {
      provider: "Antigravity",
      credentialId: credential.id,
      accountLabel: cleanLabel,
      fetchedAt: now,
      limits,
    };
  }
}

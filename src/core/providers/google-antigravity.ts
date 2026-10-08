import { getGoogleOAuthClientCredentials } from "../oauth/google";
import type { GoogleOAuthConfig } from "../oauth/google";
import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

type GoogleOAuthClientCredentials = Pick<GoogleOAuthConfig, "clientId" | "clientSecret">;

const ANTIGRAVITY_USER_AGENT = "antigravity/hub/2.8.0 (aidev_client; os_type=darwin; arch=arm64; cl=963137146)";
const DEFAULT_ENDPOINT = "https://daily-cloudcode-pa.googleapis.com";
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const FIVE_HOUR_MS = 5 * 60 * 60 * 1000;

interface AntigravityQuotaBucket {
  bucketId?: string;
  displayName?: string;
  window?: string;
  remainingFraction?: number;
  resetTime?: string;
  description?: string;
}

interface AntigravityQuotaGroup {
  displayName?: string;
  description?: string;
  buckets?: AntigravityQuotaBucket[];
}

interface AntigravityQuotaSummary {
  groups?: AntigravityQuotaGroup[];
  description?: string;
}

export class GoogleAntigravityAdapter implements ProviderAdapter {
  readonly id = "antigravity";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "antigravity" || p === "google-antigravity" || p === "google" || p === "gemini";
  }

  async refreshAccessToken(refreshToken: string, fetchImpl: typeof fetch = fetch): Promise<string> {
    return this.#refreshAccessToken(refreshToken, getGoogleOAuthClientCredentials(), fetchImpl);
  }

  async #refreshAccessToken(
    refreshToken: string,
    client: GoogleOAuthClientCredentials,
    fetchImpl: typeof fetch,
  ): Promise<string> {
    const res = await fetchImpl("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: client.clientId,
        client_secret: client.clientSecret,
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
    // 1. Auto-refresh access token with the OAuth client that issued this refresh token.
    const refreshToken = credential.metadata?.["refreshToken"] as string | undefined;
    if (refreshToken) {
      try {
        const clientId = credential.metadata?.["googleOAuthClientId"];
        const clientSecret = credential.metadata?.["googleOAuthClientSecret"];
        const hasClientId = clientId !== undefined;
        const hasClientSecret = clientSecret !== undefined;
        if (hasClientId !== hasClientSecret) {
          throw new Error("Stored Google OAuth client credentials are incomplete.");
        }
        let client: GoogleOAuthClientCredentials;
        if (hasClientId && hasClientSecret) {
          if (
            typeof clientId !== "string" || !clientId.trim() ||
            typeof clientSecret !== "string" || !clientSecret.trim()
          ) {
            throw new Error("Stored Google OAuth client credentials are invalid.");
          }
          client = getGoogleOAuthClientCredentials({ clientId, clientSecret });
        } else {
          client = getGoogleOAuthClientCredentials();
        }
        accessToken = await this.#refreshAccessToken(refreshToken, client, fetchImpl);
        credential.secret = accessToken;
        if (ctx?.onTokenRefresh) {
          ctx.onTokenRefresh(accessToken);
        }
      } catch (err) {
        if (process.env["DEBUG"] === "true") {
          console.warn("[GoogleAntigravity] Token refresh fallback to current secret:", err);
        }
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

    // 3. Quota source: v1internal:retrieveUserQuotaSummary (with retry on
    // ECONNRESET). This endpoint is the exact source backing the `agy` CLI
    // "Models & Quota" screen: per-group (Gemini / Claude+GPT) buckets with
    // explicit window ("weekly" | "5h"), remainingFraction, resetTime and
    // description. The legacy v1internal:fetchAvailableModels per-model
    // quotaInfo counters only reflect ONE backend pool per group and go
    // silently stale (they kept reporting 100% after the Gemini 5h pool was
    // exhausted), so they are no longer used at all.
    const headers: Record<string, string> = {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "User-Agent": ANTIGRAVITY_USER_AGENT,
      Connection: "close",
    };

    let response: Response | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        response = await fetchImpl(`${DEFAULT_ENDPOINT}/v1internal:retrieveUserQuotaSummary`, {
          method: "POST",
          headers,
          body: JSON.stringify({ project: projectId }),
          signal: ctx?.signal,
        });
        break;
      } catch (err: unknown) {
        const isErrObj = typeof err === "object" && err !== null;
        const isConnReset = err instanceof Error && (err.message.includes("ECONNRESET") || (isErrObj && "code" in err && err.code === "ECONNRESET"));
        if (isConnReset && attempt === 0) {
          await new Promise(res => setTimeout(res, 500));
          continue;
        }
        throw err;
      }
    }

    if (!response || !response.ok) {
      throw new Error(`Google Antigravity kota sorgusu başarısız: HTTP ${response?.status || 0} ${response?.statusText || ""}`);
    }

    // 4. Parse per-group buckets with explicit window ("weekly" | "5h").
    const summary = (await response.json()) as AntigravityQuotaSummary;

    let geminiRollingRemaining: number | undefined;
    let geminiRollingResetAt: number | undefined;
    let geminiWeeklyRemaining: number | undefined;
    let geminiWeeklyResetAt: number | undefined;

    let claudeGptRollingRemaining: number | undefined;
    let claudeGptRollingResetAt: number | undefined;
    let claudeGptWeeklyRemaining: number | undefined;
    let claudeGptWeeklyResetAt: number | undefined;

    for (const group of summary.groups ?? []) {
      const name = (group.displayName || "").toLowerCase();
      const target = name.includes("gemini") ? "gemini" : name.includes("claude") || name.includes("gpt") || name.includes("3p") ? "claudeGpt" : undefined;
      if (!target) continue;
      for (const bucket of group.buckets ?? []) {
        // OMP's canonical observation (verified in their google-antigravity
        // usage provider): exhausted Google/Gemini counters OMIT
        // remainingFraction entirely and keep only resetTime ("blocked until
        // reset"). Treat that shape as remaining 0 so a healthy sibling
        // bucket cannot mask the exhaustion; skip only buckets that carry
        // neither a fraction nor a reset time.
        const remainingFraction = typeof bucket.remainingFraction === "number"
          ? bucket.remainingFraction
          : (bucket.resetTime ? 0 : undefined);
        if (remainingFraction === undefined) continue;
        const resetAt = bucket.resetTime ? Date.parse(bucket.resetTime) : undefined;
        const window = (bucket.window || bucket.bucketId || "").toLowerCase();
        const isWeekly = window.includes("week");
        if (target === "gemini") {
          if (isWeekly) {
            geminiWeeklyRemaining = remainingFraction;
            if (resetAt !== undefined) geminiWeeklyResetAt = resetAt;
          } else {
            geminiRollingRemaining = remainingFraction;
            if (resetAt !== undefined) geminiRollingResetAt = resetAt;
          }
        } else {
          if (isWeekly) {
            claudeGptWeeklyRemaining = remainingFraction;
            if (resetAt !== undefined) claudeGptWeeklyResetAt = resetAt;
          } else {
            claudeGptRollingRemaining = remainingFraction;
            if (resetAt !== undefined) claudeGptRollingResetAt = resetAt;
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

    // 1. Gemini 5-Hour Limit: only render when a rolling-window counter was seen.
    // Missing counter => omit the card instead of rendering a fake 100% bar.
    if (geminiRollingRemaining !== undefined) {
      addLimit("gemini_5h", "Gemini: 5-Hour Limit", geminiRollingRemaining, "5h", FIVE_HOUR_MS, geminiRollingResetAt);
    }

    // 2. Gemini Weekly Limit: never fabricate from the rolling window.
    if (geminiWeeklyRemaining !== undefined) {
      addLimit("gemini_weekly", "Gemini: Weekly Limit", geminiWeeklyRemaining, "weekly", WEEK_MS, geminiWeeklyResetAt ?? now + WEEK_MS);
    }

    // 3. Claude & GPT 5-Hour Limit
    if (claudeGptRollingRemaining !== undefined) {
      addLimit("claude_gpt_5h", "Claude & GPT: 5-Hour Limit", claudeGptRollingRemaining, "5h", FIVE_HOUR_MS, claudeGptRollingResetAt);
    }

    // 4. Claude & GPT Weekly Limit
    if (claudeGptWeeklyRemaining !== undefined) {
      addLimit("claude_gpt_weekly", "Claude & GPT: Weekly Limit", claudeGptWeeklyRemaining, "weekly", WEEK_MS, claudeGptWeeklyResetAt ?? now + WEEK_MS);
    }

    if (limits.length === 0) {
      throw new Error("Google Antigravity kota yanıtında pencere sayacı bulunamadı.");
    }

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

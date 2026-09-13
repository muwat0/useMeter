import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageAmount, UsageLimit, UsageReport, UsageStatus, UsageWindow } from "../../types";

const DEFAULT_ENDPOINT = "https://cloudcode-pa.googleapis.com";
const DEFAULT_GEMINI_CLI_USER_AGENT = "GeminiCLI/0.46.0/gemini-3.1-pro-preview (linux; x64; terminal)";
const CLIENT_METADATA = "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI";

interface RawLoadCodeAssistResponse {
  cloudaicompanionProject?: string | { id?: string };
  currentTier?: { id?: string; name?: string };
}

interface RawQuotaBucket {
  modelId?: string;
  remainingFraction?: number;
  resetTime?: string;
}

interface RawRetrieveUserQuotaResponse {
  buckets?: RawQuotaBucket[];
}

function extractOAuthToken(credential: StoredCredential): string {
  if (credential.credentialType !== "oauth") {
    throw new Error(
      "Google Gemini CLI usage requires an OAuth access token. API key authentication is not supported for quota endpoints."
    );
  }

  const rawSecret = credential.secret?.trim();
  if (!rawSecret) {
    throw new Error("Missing OAuth access token for Google Gemini CLI.");
  }

  if (rawSecret.startsWith("{") && rawSecret.endsWith("}")) {
    try {
      const parsed = JSON.parse(rawSecret) as Record<string, unknown>;
      const token = parsed["access_token"] ?? parsed["accessToken"] ?? parsed["token"];
      if (typeof token === "string" && token.trim()) {
        return token.trim();
      }
    } catch {
      // Non-JSON secret string fallback
    }
  }

  return rawSecret;
}

function extractProjectId(credential: StoredCredential, loadResponse?: RawLoadCodeAssistResponse): string | undefined {
  const metadataProject = credential.metadata?.["projectId"] ?? credential.metadata?.["cloudaicompanionProject"];
  if (typeof metadataProject === "string" && metadataProject.trim()) {
    return metadataProject.trim();
  }

  if (!loadResponse) return undefined;

  if (typeof loadResponse.cloudaicompanionProject === "string" && loadResponse.cloudaicompanionProject.trim()) {
    return loadResponse.cloudaicompanionProject.trim();
  }

  if (
    loadResponse.cloudaicompanionProject &&
    typeof loadResponse.cloudaicompanionProject === "object" &&
    typeof loadResponse.cloudaicompanionProject.id === "string" &&
    loadResponse.cloudaicompanionProject.id.trim()
  ) {
    return loadResponse.cloudaicompanionProject.id.trim();
  }

  return undefined;
}

function parseWindow(resetTime?: string): UsageWindow {
  if (!resetTime || typeof resetTime !== "string") {
    return {
      id: "quota",
      label: "Quota window",
    };
  }

  const parsed = Date.parse(resetTime);
  if (Number.isNaN(parsed)) {
    return {
      id: "quota",
      label: "Quota window",
    };
  }

  return {
    id: `reset-${parsed}`,
    label: "Quota window",
    resetsAt: parsed,
  };
}

function buildAmount(remainingFraction?: number): UsageAmount {
  if (remainingFraction === undefined || !Number.isFinite(remainingFraction)) {
    return { unit: "percent" };
  }

  const remaining = Math.min(Math.max(remainingFraction, 0), 1);
  const used = Math.min(Math.max(1 - remaining, 0), 1);

  return {
    unit: "percent",
    used: Math.round(used * 1000) / 10,
    remaining: Math.round(remaining * 1000) / 10,
    limit: 100,
    usedFraction: used,
  };
}

function calculateStatus(amount: UsageAmount): UsageStatus {
  if (amount.usedFraction === undefined) {
    return "unknown";
  }
  if (amount.usedFraction >= 1) {
    return "exhausted";
  }
  if (amount.usedFraction >= 0.9) {
    return "warning";
  }
  return "ok";
}

export class GoogleGeminiCliAdapter implements ProviderAdapter {
  readonly id = "google-gemini-cli";

  supports(provider: string): boolean {
    const p = provider.toLowerCase().trim();
    return p === "google-gemini-cli" || p === "gemini-cli";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const accessToken = extractOAuthToken(credential);
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();

    const baseUrl = (
      (credential.metadata?.["baseUrl"] as string | undefined) ||
      (credential.metadata?.["endpoint"] as string | undefined) ||
      DEFAULT_ENDPOINT
    ).replace(/\/$/, "");

    const headers: Record<string, string> = {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "User-Agent": DEFAULT_GEMINI_CLI_USER_AGENT,
      "Client-Metadata": CLIENT_METADATA,
    };

    // 1. Call loadCodeAssist
    let loadResponse: RawLoadCodeAssistResponse | undefined;
    const metadataProjectId = typeof credential.metadata?.["projectId"] === "string" ? credential.metadata["projectId"] : undefined;

    try {
      const loadRes = await fetchImpl(`${baseUrl}/v1internal:loadCodeAssist`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          ...(metadataProjectId ? { cloudaicompanionProject: metadataProjectId } : {}),
          metadata: {
            ideType: "IDE_UNSPECIFIED",
            platform: "PLATFORM_UNSPECIFIED",
            pluginType: "GEMINI",
          },
        }),
        signal: ctx?.signal,
      });

      if (loadRes.ok) {
        loadResponse = (await loadRes.json()) as RawLoadCodeAssistResponse;
      } else if (loadRes.status === 401 || loadRes.status === 403) {
        const errText = await loadRes.text().catch(() => "");
        throw new Error(`Google Gemini CLI authentication failed (HTTP ${loadRes.status}): ${errText || "Invalid token or unauthorized"}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes("Google Gemini CLI authentication failed")) {
        throw err;
      }
    }

    const projectId = extractProjectId(credential, loadResponse);

    // 2. Call retrieveUserQuota
    const quotaRes = await fetchImpl(`${baseUrl}/v1internal:retrieveUserQuota`, {
      method: "POST",
      headers,
      body: JSON.stringify(projectId ? { project: projectId } : {}),
      signal: ctx?.signal,
    });

    if (!quotaRes.ok) {
      const errorText = await quotaRes.text().catch(() => "");
      throw new Error(
        `Google Gemini CLI retrieveUserQuota failed (HTTP ${quotaRes.status}): ${errorText || "Unable to retrieve quota"}`
      );
    }

    const rawQuotaJson = (await quotaRes.json()) as unknown;
    if (typeof rawQuotaJson !== "object" || rawQuotaJson === null) {
      throw new Error("Google Gemini CLI returned an invalid response structure for quota.");
    }

    const quotaResponse = rawQuotaJson as RawRetrieveUserQuotaResponse;
    const rawBuckets = Array.isArray(quotaResponse.buckets) ? quotaResponse.buckets : [];

    if (rawBuckets.length === 0) {
      throw new Error("No quota bucket data available for this Google Gemini CLI account.");
    }

    const limits: UsageLimit[] = [];

    rawBuckets.forEach((bucket, index) => {
      const remainingFraction = typeof bucket.remainingFraction === "number" ? bucket.remainingFraction : undefined;
      const resetTime = typeof bucket.resetTime === "string" ? bucket.resetTime : undefined;
      const window = parseWindow(resetTime);
      const amount = buildAmount(remainingFraction);
      const status = calculateStatus(amount);

      const limitId = window.resetsAt ? `gemini-quota-${window.resetsAt}` : `gemini-quota-${index}`;
      const label = window.resetsAt ? "Gemini window quota" : "Gemini quota";

      limits.push({
        id: limitId,
        label,
        amount,
        window,
        status,
      });
    });

    return {
      provider: credential.provider || this.id,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
    };
  }
}

import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus } from "../../types";

const INTL_BASE_URL = "https://api.minimax.io";
const REMAINS_PATH = "/v1/token_plan/remains";
const STATUS_EXHAUSTED = 2;
const STATUS_UNLIMITED = 3;
const HOUR_MS = 60 * 60 * 1000;
const SHARED_BUCKET = "general";

interface MiniMaxBaseResp {
  status_code?: unknown;
  status_msg?: unknown;
}

interface MiniMaxRemainsEntry {
  model_name?: unknown;
  start_time?: unknown;
  end_time?: unknown;
  current_interval_remaining_percent?: unknown;
  current_interval_total_count?: unknown;
  current_interval_usage_count?: unknown;
  current_interval_status?: unknown;
  weekly_start_time?: unknown;
  weekly_end_time?: unknown;
  current_weekly_remaining_percent?: unknown;
  current_weekly_total_count?: unknown;
  current_weekly_usage_count?: unknown;
  current_weekly_status?: unknown;
}

interface MiniMaxRemainsPayload {
  base_resp?: MiniMaxBaseResp;
  model_remains?: unknown[];
}

interface TokenPlanBucket {
  modelName: string;
  intervalStart?: number;
  intervalEnd?: number;
  intervalRemainingPercent?: number;
  intervalTotalCount?: number;
  intervalUsageCount?: number;
  intervalStatus?: number;
  weeklyStart?: number;
  weeklyEnd?: number;
  weeklyRemainingPercent?: number;
  weeklyTotalCount?: number;
  weeklyUsageCount?: number;
  weeklyStatus?: number;
}

interface CredentialJsonShape {
  token?: unknown;
  apiKey?: unknown;
  access_token?: unknown;
  key?: unknown;
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function parsePositiveTimestamp(value: unknown): number | undefined {
  const num = toNumber(value);
  if (num === undefined || num <= 0) return undefined;
  return num < 100_000_000_000 ? Math.round(num * 1000) : Math.round(num);
}

function usedFractionFromRemainingPercent(value: unknown): number | undefined {
  const parsed = toNumber(value);
  if (parsed === undefined || !Number.isFinite(parsed)) return undefined;
  return Math.min(1, Math.max(0, (100 - parsed) / 100));
}

function parseBucket(value: unknown): TokenPlanBucket | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const entry = value as MiniMaxRemainsEntry;
  const modelName = typeof entry.model_name === "string" ? entry.model_name.trim() : "";
  if (!modelName) return null;
  return {
    modelName,
    intervalStart: parsePositiveTimestamp(entry.start_time),
    intervalEnd: parsePositiveTimestamp(entry.end_time),
    intervalRemainingPercent: toNumber(entry.current_interval_remaining_percent),
    intervalTotalCount: toNumber(entry.current_interval_total_count),
    intervalUsageCount: toNumber(entry.current_interval_usage_count),
    intervalStatus: toNumber(entry.current_interval_status),
    weeklyStart: parsePositiveTimestamp(entry.weekly_start_time),
    weeklyEnd: parsePositiveTimestamp(entry.weekly_end_time),
    weeklyRemainingPercent: toNumber(entry.current_weekly_remaining_percent),
    weeklyTotalCount: toNumber(entry.current_weekly_total_count),
    weeklyUsageCount: toNumber(entry.current_weekly_usage_count),
    weeklyStatus: toNumber(entry.current_weekly_status),
  };
}

function isUnavailablePlan(bucket: TokenPlanBucket): boolean {
  return (
    bucket.intervalTotalCount === 0 &&
    bucket.weeklyTotalCount === 0 &&
    bucket.intervalStatus === STATUS_UNLIMITED &&
    bucket.weeklyStatus === STATUS_UNLIMITED
  );
}

function calculateUsageStatus(usedFraction: number): UsageStatus {
  if (usedFraction >= 1) return "exhausted";
  if (usedFraction >= 0.8) return "warning";
  return "ok";
}

function extractBearerToken(secret: string): string {
  const trimmed = secret.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        const shape = parsed as CredentialJsonShape;
        if (typeof shape.token === "string" && shape.token.trim()) return shape.token.trim();
        if (typeof shape.apiKey === "string" && shape.apiKey.trim()) return shape.apiKey.trim();
        if (typeof shape.access_token === "string" && shape.access_token.trim()) return shape.access_token.trim();
        if (typeof shape.key === "string" && shape.key.trim()) return shape.key.trim();
      }
    } catch {}
  }
  return trimmed;
}

export class MiniMaxAdapter implements ProviderAdapter {
  readonly id = "minimax-code";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "minimax-code" || p === "minimax";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const token = extractBearerToken(credential.secret);

    if (!token) {
      throw new Error("MiniMax credential does not contain a valid API key or token");
    }

    const response = await fetchImpl(`${INTL_BASE_URL}${REMAINS_PATH}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      signal: ctx?.signal,
    });

    if (!response.ok) {
      throw new Error(`MiniMax API HTTP ${response.status}: ${response.statusText}`);
    }

    const rawPayload: unknown = await response.json();
    if (typeof rawPayload !== "object" || rawPayload === null || Array.isArray(rawPayload)) {
      throw new Error("Invalid response format from MiniMax token_plan endpoint");
    }

    const payload = rawPayload as MiniMaxRemainsPayload;
    if (payload.base_resp && typeof payload.base_resp === "object") {
      const statusCode = toNumber(payload.base_resp.status_code);
      if (statusCode !== undefined && statusCode !== 0) {
        const statusMsg = typeof payload.base_resp.status_msg === "string" ? payload.base_resp.status_msg : "Unknown error";
        throw new Error(`MiniMax API rejected token plan: [${statusCode}] ${statusMsg}`);
      }
    }

    if (!Array.isArray(payload.model_remains)) {
      throw new Error("MiniMax response missing model_remains array");
    }

    const limits: UsageLimit[] = [];
    let generalBucket: TokenPlanBucket | null = null;
    const candidateBuckets: TokenPlanBucket[] = [];

    for (const entry of payload.model_remains) {
      const bucket = parseBucket(entry);
      if (!bucket) continue;
      if (isUnavailablePlan(bucket)) continue;

      if (bucket.modelName.toLowerCase() === SHARED_BUCKET) {
        generalBucket = bucket;
      } else {
        candidateBuckets.push(bucket);
      }
    }

    // Target the primary plan bucket: prefer 'general' (the plan-wide shared bucket)
    const targetBucket = generalBucket ?? candidateBuckets[0];

    if (targetBucket) {
      // 1. Interval / 5h Window
      const intervalDuration =
        targetBucket.intervalStart !== undefined && targetBucket.intervalEnd !== undefined
          ? targetBucket.intervalEnd - targetBucket.intervalStart
          : undefined;

      let intervalFraction = usedFractionFromRemainingPercent(targetBucket.intervalRemainingPercent);
      if (targetBucket.intervalStatus === STATUS_EXHAUSTED) {
        intervalFraction = 1;
      }

      if (intervalFraction !== undefined) {
        let windowId = "5h";
        let windowLabel = "5-Hour Window";
        if (intervalDuration !== undefined && intervalDuration > 0) {
          const hours = Math.round(intervalDuration / HOUR_MS);
          if (hours > 0) {
            windowId = `${hours}h`;
            windowLabel = `${hours}-Hour Window`;
          }
        }

        const notes: string[] = [];
        if (targetBucket.intervalTotalCount !== undefined && targetBucket.intervalTotalCount > 0) {
          notes.push(`Requests: ${targetBucket.intervalUsageCount ?? 0}/${targetBucket.intervalTotalCount}`);
        }

        limits.push({
          id: "minimax_5h",
          label: `Rolling Quota (${windowLabel})`,
          amount: {
            used: Math.round(intervalFraction * 1000) / 10,
            remaining: Math.round((1 - intervalFraction) * 1000) / 10,
            usedFraction: intervalFraction,
            unit: "percent",
          },
          window: {
            id: windowId,
            label: windowLabel,
            durationMs: intervalDuration,
            resetsAt: targetBucket.intervalEnd,
            resetLabel: "resets",
          },
          status: calculateUsageStatus(intervalFraction),
          notes: notes.length > 0 ? notes : undefined,
        });
      }

      // 2. Weekly Window
      const weeklyDuration =
        targetBucket.weeklyStart !== undefined && targetBucket.weeklyEnd !== undefined
          ? targetBucket.weeklyEnd - targetBucket.weeklyStart
          : 7 * 24 * HOUR_MS;

      let weeklyFraction = usedFractionFromRemainingPercent(targetBucket.weeklyRemainingPercent);
      if (targetBucket.weeklyStatus === STATUS_EXHAUSTED) {
        weeklyFraction = 1;
      }

      if (weeklyFraction !== undefined) {
        const weeklyNotes: string[] = [];
        if (targetBucket.weeklyTotalCount !== undefined && targetBucket.weeklyTotalCount > 0) {
          weeklyNotes.push(`Requests: ${targetBucket.weeklyUsageCount ?? 0}/${targetBucket.weeklyTotalCount}`);
        }

        limits.push({
          id: "minimax_weekly",
          label: "Weekly Quota",
          amount: {
            used: Math.round(weeklyFraction * 1000) / 10,
            remaining: Math.round((1 - weeklyFraction) * 1000) / 10,
            usedFraction: weeklyFraction,
            unit: "percent",
          },
          window: {
            id: "7d",
            label: "Weekly Window",
            durationMs: weeklyDuration,
            resetsAt: targetBucket.weeklyEnd,
            resetLabel: "resets",
          },
          status: calculateUsageStatus(weeklyFraction),
          notes: weeklyNotes.length > 0 ? weeklyNotes : undefined,
        });
      }
    }

    return {
      provider: credential.provider,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits,
    };
  }
}

import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus, UsageWindow } from "../../types";
import { refreshKimiToken } from "../oauth/kimi";
const DEFAULT_BASE_URL = "https://api.kimi.com/coding/v1";
const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
const WEEK_MS = 7 * DAY_MS;
const MANAGED_USAGE_WINDOWS = [
  {
    key: "limit_5h",
    id: "5h",
    label: "5 Saatlik Kayan Kota",
    windowLabel: "5 Saatlik Kayan Pencere",
    durationMs: 5 * HOUR_MS,
  },
  {
    key: "limit_7d",
    id: "7d",
    label: "Haftalık Kota",
    windowLabel: "Haftalık Pencere",
    durationMs: WEEK_MS,
  },
  {
    key: "limit_month_total",
    id: "monthly",
    label: "Aylık Kota",
    windowLabel: "Aylık Pencere",
    durationMs: undefined,
  },
] as const;


interface KimiTokenJson {
  access_token?: unknown;
  token?: unknown;
}

interface KimiUsageDetail {
  used?: unknown;
  limit?: unknown;
  remaining?: unknown;
  reset_time?: unknown;
  resetTime?: unknown;
  reset_at?: unknown;
  resetAt?: unknown;
  reset_in?: unknown;
  resetIn?: unknown;
  ttl?: unknown;
  name?: unknown;
  title?: unknown;
  scope?: unknown;
}

interface KimiWindowData {
  duration?: unknown;
  timeUnit?: unknown;
  reset_time?: unknown;
  resetTime?: unknown;
  reset_at?: unknown;
  resetAt?: unknown;
  reset_in?: unknown;
  resetIn?: unknown;
  ttl?: unknown;
}

interface KimiLimitItem {
  detail?: KimiUsageDetail;
  window?: KimiWindowData;
  name?: unknown;
  title?: unknown;
  scope?: unknown;
  used?: unknown;
  limit?: unknown;
  remaining?: unknown;
  reset_time?: unknown;
  resetTime?: unknown;
  reset_at?: unknown;
  resetAt?: unknown;
  reset_in?: unknown;
  resetIn?: unknown;
  duration?: unknown;
  timeUnit?: unknown;
}

interface KimiUsagePayload {
  usage?: KimiUsageDetail;
  limits?: unknown;
  usages?: unknown;
  error?: {
    message?: unknown;
  };
}


interface ParsedUsageRow {
  label: string;
  used?: number;
  limit?: number;
  remaining?: number;
  resetsAt?: number;
  window?: UsageWindow;
  notes?: string[];
}


const SCHEMA_CLUE_MAX_DEPTH = 5;
const SCHEMA_CLUE_MAX_KEYS = 32;
const SCHEMA_CLUE_MAX_ENTRIES = 32;
const SCHEMA_CLUE_MAX_LENGTH = 640;
const SAFE_SCHEMA_CLUE_KEYS: Record<string, true> = {
  usage: true,
  usages: true,
  used_ratio: true,
  limit_5h: true,
  limit_7d: true,
  limit_month_total: true,
  limit_month_code: true,
  boosterwallet: true,

  limits: true,
  data: true,
  result: true,
  error: true,
  message: true,
  detail: true,
  window: true,
  quota: true,
  quotas: true,
  remaining: true,
  used: true,
  limit: true,
  reset_time: true,
  resettime: true,
  reset_at: true,
  resetat: true,
  reset_in: true,
  resetin: true,
  ttl: true,
  duration: true,
  timeunit: true,
  unit: true,
  name: true,
  title: true,
  scope: true,
  items: true,
  values: true,
  status: true,
  type: true,
  code: true,
  balance: true,
  credits: true,
  plan: true,
  model: true,
  models: true,
  hourly: true,
  daily: true,
  weekly: true,
  monthly: true,
  premium: true,
  standard: true,
};

function isSensitiveSchemaKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  return /token|secret|password|credential|authorization|cookie|email|account|user|profile|phone|address|session|device|identity|personal|apikey|clientid|auth/.test(
    normalized,
  );
}

function describeKimiUsageSchema(payload: unknown): string {

  const paths: string[] = [];
  let inspectedKeys = 0;
  let truncated = false;

  const visit = (value: unknown, path: string, depth: number): void => {
    if (paths.length >= SCHEMA_CLUE_MAX_ENTRIES) {
      truncated = true;
      return;
    }
    const valType = value === null ? "null" : Array.isArray(value) ? "array" : typeof value === "object" ? "object" : typeof value;
    paths.push(`${path}=${valType}`);

    if (depth >= SCHEMA_CLUE_MAX_DEPTH) {
      if (value !== null && typeof value === "object") truncated = true;
      return;
    }

    if (Array.isArray(value)) {
      if (value.length > 0) visit(value[0], `${path}[]`, depth + 1);
      if (value.length > 1) truncated = true;
      return;
    }
    if (value === null || typeof value !== "object") return;

    for (const key in value) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
      if (inspectedKeys >= SCHEMA_CLUE_MAX_KEYS) {
        truncated = true;
        break;
      }
      inspectedKeys += 1;
      if (isSensitiveSchemaKey(key)) continue;

      const normalizedKey = key.toLowerCase();
      const segment = Object.prototype.hasOwnProperty.call(SAFE_SCHEMA_CLUE_KEYS, normalizedKey)
        ? normalizedKey
        : "[redacted-key]";
      visit((value as Record<string, unknown>)[key], `${path}.${segment}`, depth + 1);
    }
  };
  const classifyFailure = (): string => {
    if (payload !== null && typeof payload === "object" && !Array.isArray(payload)) {
      try {
        let hasEnumerableKey = false;
        let allSensitive = true;
        for (const key in payload) {
          if (!Object.prototype.hasOwnProperty.call(payload, key)) continue;
          hasEnumerableKey = true;
          if (!isSensitiveSchemaKey(key)) {
            allSensitive = false;
            break;
          }
        }
        if (!hasEnumerableKey) return "boş JSON nesnesi";
        if (allSensitive) return "yalnızca hassas anahtarlar içeren nesne";
      } catch {
        return "unsupported schema";
      }
    }
    return "unsupported schema";
  };


  try {
    visit(payload, "$", 0);
  } catch {
    return classifyFailure();
  }

  if (paths.length < 2) return classifyFailure();
  const clue = paths.join("; ") + (truncated ? "; …" : "");
  return clue.length <= SCHEMA_CLUE_MAX_LENGTH ? clue : `${clue.slice(0, SCHEMA_CLUE_MAX_LENGTH - 3)}...`;
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

function parseIsoTimestamp(value: unknown): number | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const parsed = Date.parse(value.trim());
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseResetTime(data: KimiUsageDetail | KimiWindowData, nowMs: number): number | undefined {
  const timeCandidates = [data.reset_at, data.resetAt, data.reset_time, data.resetTime];
  for (const val of timeCandidates) {
    if (typeof val === "string" && val.trim()) {
      const parsed = parseIsoTimestamp(val);
      if (parsed !== undefined) return parsed;
    }
    if (typeof val === "number" && Number.isFinite(val) && val > 0) {
      return val > 1_000_000_000_000 ? Math.round(val) : Math.round(val * 1000);
    }
  }

  const secondsCandidates = [data.reset_in, data.resetIn, data.ttl];
  for (const val of secondsCandidates) {
    const seconds = toNumber(val);
    if (seconds !== undefined && seconds > 0) {
      return Math.round(nowMs + seconds * 1000);
    }
  }

  return undefined;
}

function formatDurationLabel(duration: number, timeUnit: string): string | undefined {
  const upper = timeUnit.toUpperCase();
  if (upper.includes("MINUTE")) {
    if (duration >= 60 && duration % 60 === 0) return `${duration / 60} Hour`;
    return `${duration} Minute`;
  }
  if (upper.includes("HOUR")) return `${duration} Hour`;
  if (upper.includes("DAY")) return `${duration} Day`;
  if (upper.includes("SECOND")) return `${duration} Second`;
  return undefined;
}

function canonicalWindowId(durationMs: number): string {
  if (durationMs > 0 && durationMs % DAY_MS === 0) return `${durationMs / DAY_MS}d`;
  if (durationMs > 0 && durationMs % HOUR_MS === 0) return `${durationMs / HOUR_MS}h`;
  const minutes = Math.round(durationMs / MINUTE_MS);
  return minutes > 0 ? `${minutes}m` : "default";
}

function buildWindow(windowData: KimiWindowData, nowMs: number): UsageWindow | undefined {
  const duration = toNumber(windowData.duration);
  const timeUnit = typeof windowData.timeUnit === "string" ? windowData.timeUnit : "";
  const label = duration !== undefined && timeUnit ? formatDurationLabel(duration, timeUnit) : undefined;
  const resetsAt = parseResetTime(windowData, nowMs);

  if (duration === undefined && !label && !resetsAt) return undefined;
  let durationMs: number | undefined;
  if (duration !== undefined) {
    const upper = timeUnit.toUpperCase();
    if (upper.includes("MINUTE")) durationMs = duration * MINUTE_MS;
    else if (upper.includes("HOUR")) durationMs = duration * HOUR_MS;
    else if (upper.includes("DAY")) durationMs = duration * DAY_MS;
    else if (upper.includes("WEEK")) durationMs = duration * WEEK_MS;
    else if (upper.includes("SECOND")) durationMs = duration * 1000;
  }

  const winId = durationMs !== undefined ? canonicalWindowId(durationMs) : "default";
  return {
    id: winId,
    label: label ?? (winId === "5h" ? "5 Saatlik Kayan Pencere" : "Usage window"),
    durationMs,
    resetsAt,
    resetLabel: "Sıfırlanma",
  };
}

function buildUsageRow(data: KimiUsageDetail, defaultLabel: string, nowMs: number): ParsedUsageRow | null {
  const limit = toNumber(data.limit);
  let used = toNumber(data.used);
  const remaining = toNumber(data.remaining);
  if (used === undefined && remaining !== undefined && limit !== undefined) {
    used = limit - remaining;
  }

  if (used === undefined && limit === undefined) return null;
  const resetsAt = parseResetTime(data, nowMs);
  const label =
    typeof data.name === "string" && data.name.trim()
      ? data.name.trim()
      : typeof data.title === "string" && data.title.trim()
        ? data.title.trim()
        : defaultLabel;

  return {
    label,
    used,
    limit,
    remaining,
    resetsAt,
  };
}

function parseManagedRatio(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value !== "string") return undefined;

  const trimmed = value.trim();
  if (!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(trimmed)) return undefined;
  const ratio = Number(trimmed);
  return Number.isFinite(ratio) ? ratio : undefined;
}

function parseManagedResetTime(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const resetTime = value.trim();
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(
      resetTime,
    );
  if (!match) return undefined;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = Number(match[8] ?? 0);
  const offsetMinute = Number(match[9] ?? 0);
  const isLeapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, isLeapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > (daysInMonth ?? 0) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return undefined;
  }

  const timestamp = Date.parse(resetTime);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

function buildManagedUsageLimits(usages: unknown): UsageLimit[] {
  if (typeof usages !== "object" || usages === null || Array.isArray(usages)) return [];
  const entries = usages as Record<string, unknown>;
  const limits: UsageLimit[] = [];

  for (const entryDefinition of MANAGED_USAGE_WINDOWS) {
    const rawEntry = entries[entryDefinition.key];
    if (typeof rawEntry !== "object" || rawEntry === null || Array.isArray(rawEntry)) continue;
    const entry = rawEntry as Record<string, unknown>;
    const ratio = parseManagedRatio(entry["used_ratio"]);
    if (ratio === undefined) continue;

    const usedFraction = Math.min(Math.max(ratio, 0), 1);
    const resetsAt = parseManagedResetTime(entry["reset_time"]);
    let notes: string[] | undefined;
    if (entryDefinition.key === "limit_month_total") {
      const rawCodeEntry = entries["limit_month_code"];
      if (typeof rawCodeEntry === "object" && rawCodeEntry !== null && !Array.isArray(rawCodeEntry)) {
        const codeRatio = parseManagedRatio((rawCodeEntry as Record<string, unknown>)["used_ratio"]);
        if (codeRatio !== undefined) {
          const clampedCode = Math.min(Math.max(codeRatio, 0), 1);
          const codePercent = Number((clampedCode * 100).toFixed(1));
          notes = [`Kod kullanımı: %${codePercent}`];
        }
      }
    }

    const row: ParsedUsageRow = {
      label: entryDefinition.label,
      used: usedFraction,
      limit: 1,
      remaining: 1 - usedFraction,
      resetsAt,
      window: {
        id: entryDefinition.id,
        label: entryDefinition.windowLabel,
        durationMs: entryDefinition.durationMs,
        resetsAt,
        resetLabel: "Sıfırlanma",
      },
      notes,
    };
    const limit = toUsageLimit(row, limits.length);
    if (limit) limits.push(limit);
  }

  // month_code is a breakdown of month_total, never a separate full quota.
  return limits;
}
function isExplicitEmptyUsagePayload(payload: unknown): boolean {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return false;
  const record = payload as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 0) return true;
  if (!Object.prototype.hasOwnProperty.call(record, "usages")) return false;

  const usages = record["usages"];
  if (typeof usages !== "object" || usages === null || Array.isArray(usages) || Object.keys(usages).length !== 0) {
    return false;
  }

  for (const key of keys) {
    if (key === "usages") continue;
    const value = record[key];
    if (key === "boosterWallet" && value === null) continue;
    if (key === "goods_version" && (value === 1 || value === 2)) continue;
    return false;
  }
  return true;
}



function extractBearerToken(secret: string): string {
  const trimmed = secret.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        const shape = parsed as KimiTokenJson;
        if (typeof shape.access_token === "string" && shape.access_token.trim()) {
          return shape.access_token.trim();
        }
        if (typeof shape.token === "string" && shape.token.trim()) {
          return shape.token.trim();
        }
      }
    } catch {}
  }
  return trimmed;
}


function toUsageLimit(row: ParsedUsageRow, index: number): UsageLimit | null {
  if (row.limit === undefined || row.limit <= 0 || row.used === undefined) {
    return null;
  }

  const usedFraction = Math.min(Math.max(row.used / row.limit, 0), 1);
  const usedPercent = Number((usedFraction * 100).toFixed(1));
  const remainingPercent = Number(Math.max(0, 100 - usedPercent).toFixed(1));

  const windowId = row.window?.id ?? "default";
  const limitId = windowId !== "default" ? `kimi-code-${windowId}` : `kimi-code-${index}`;

  const window: UsageWindow | undefined = row.window
    ? {
        ...row.window,
        resetsAt: row.window.resetsAt ?? row.resetsAt,
        resetLabel: "Sıfırlanma",
      }
    : row.resetsAt
      ? {
          id: "default",
          label: "Pencere",
          resetsAt: row.resetsAt,
          resetLabel: "Sıfırlanma",
        }
      : undefined;

  let label = row.label;
  if (windowId === "5h") {
    label = "5 Saatlik Kayan Kota";
  } else if (windowId === "7d") {
    label = "Haftalık Kota";
  } else if (windowId === "monthly") {
    label = "Aylık Kota";
  }

  const status: UsageStatus = usedFraction >= 1 ? "exhausted" : usedFraction >= 0.8 ? "warning" : "ok";

  return {
    id: limitId,
    label,
    amount: {
      used: usedPercent,
      limit: 100,
      remaining: remainingPercent,
      usedFraction,
      unit: "percent",
    },
    window,
    status,
    notes: row.notes,
  };
}

export class KimiCodeAdapter implements ProviderAdapter {
  readonly id = "kimi-code";

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === "kimi-code" || p === "kimi" || p === "kimi_code" || p === "moonshot";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    if (credential.credentialType === "api_key") {
      throw new Error("Kimi Code kullanım sorgusu OAuth kimlik doğrulaması gerektirir; standart API anahtarları desteklenmez.");
    }

    if (credential.credentialType !== "oauth") {
      throw new Error("Kimi Code kullanım uç noktası OAuth kimlik doğrulaması gerektirir; diğer kimlik tipleri desteklenmez.");
    }

    let token = extractBearerToken(credential.secret);
    if (!token) {
      throw new Error("Kimi Code OAuth erişim belirteci (access token) eksik veya boş.");
    }

    if (token.startsWith("sk-") && !token.includes("ey")) {
      throw new Error("Kimi Code kullanım API'si yalnızca OAuth belirteçlerini destekler; standart API anahtarları desteklenmez.");
    }

    const refreshToken = credential.metadata?.["refreshToken"] as string | undefined;
    let deviceId = credential.metadata?.["deviceId"] as string | undefined;
    let isExpired = false;

    try {
      const parts = token.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        if (!deviceId && typeof payload.device_id === "string") {
          deviceId = payload.device_id;
        }
        if (typeof payload.exp === "number" && payload.exp * 1000 - Date.now() < 60_000) {
          isExpired = true;
        }
      }
    } catch {}

    if (isExpired && refreshToken) {
      try {
        const refreshed = await refreshKimiToken(refreshToken, deviceId, { fetch: ctx?.fetch, signal: ctx?.signal });
        ctx?.signal?.throwIfAborted();
        token = refreshed.accessToken;
        credential.secret = refreshed.accessToken;
        const metaUpdates: Record<string, unknown> = {};
        if (refreshed.refreshToken) {
          credential.metadata = { ...(credential.metadata || {}), refreshToken: refreshed.refreshToken };
          metaUpdates["refreshToken"] = refreshed.refreshToken;
        }
        if (ctx?.onTokenRefresh) {
          ctx.onTokenRefresh(refreshed.accessToken, metaUpdates);
        }
      } catch (err) {
        if (ctx?.signal?.aborted) throw err;
        if (process.env["DEBUG"] === "true") {
          console.warn("[KimiCode] Pre-emptive token refresh failed:", err);
        }
      }
    }
    ctx?.signal?.throwIfAborted();

    const fetchImpl = ctx?.fetch ?? fetch;
    const nowMs = Date.now();
    const envBase = process.env["KIMI_CODE_BASE_URL"]?.trim();
    const baseUrl = envBase ? envBase.replace(/\/+$/, "") : DEFAULT_BASE_URL;
    const url = `${baseUrl}/usages`;

    let response = await fetchImpl(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
      signal: ctx?.signal,
    });

    if (response.status === 401 && refreshToken) {
      try {
        const refreshed = await refreshKimiToken(refreshToken, deviceId, { fetch: ctx?.fetch, signal: ctx?.signal });
        ctx?.signal?.throwIfAborted();
        token = refreshed.accessToken;
        credential.secret = refreshed.accessToken;
        const metaUpdates: Record<string, unknown> = {};
        if (refreshed.refreshToken) {
          credential.metadata = { ...(credential.metadata || {}), refreshToken: refreshed.refreshToken };
          metaUpdates["refreshToken"] = refreshed.refreshToken;
        }
        if (ctx?.onTokenRefresh) {
          ctx.onTokenRefresh(refreshed.accessToken, metaUpdates);
        }
        response = await fetchImpl(url, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/json",
          },
          signal: ctx?.signal,
        });
      } catch (err) {
        if (ctx?.signal?.aborted) throw err;
        if (process.env["DEBUG"] === "true") {
          console.warn("[KimiCode] 401 token refresh retry failed:", err);
        }
      }
    }

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error(`Kimi Code yetkilendirme hatası: HTTP ${response.status} (Geçersiz veya süresi dolmuş OAuth token).`);
      }
      if (response.status === 429) {
        throw new Error("Kimi Code kullanım sorgusu rate limit'e takıldı (HTTP 429).");
      }
      throw new Error(`Kimi Code kullanım sorgusu başarısız: HTTP ${response.status} ${response.statusText}`);
    }

    let rawPayload: unknown;
    try {
      rawPayload = await response.json();
    } catch (err) {
      throw new Error(`Kimi Code API yanıtı JSON olarak ayrıştırılamadı: ${String(err)}`);
    }

    if (typeof rawPayload !== "object" || rawPayload === null || Array.isArray(rawPayload)) {
      throw new Error("Kimi Code API geçersiz bir yanıt döndürdü.");
    }

    const payload = rawPayload as KimiUsagePayload;
    const managedLimits = buildManagedUsageLimits(payload.usages);
    // Prefer first-party windows when present; legacy parsing remains for custom proxies.
    const limits: UsageLimit[] = managedLimits.length > 0 ? managedLimits : [];

    if (managedLimits.length === 0) {
      if (typeof payload.usage === "object" && payload.usage !== null && !Array.isArray(payload.usage)) {
        const summary = buildUsageRow(payload.usage, "Haftalık Kota", nowMs);
        if (summary) {
          summary.window = {
            id: "7d",
            label: "Haftalık Pencere",
            durationMs: WEEK_MS,
            resetsAt: summary.resetsAt,
            resetLabel: "Sıfırlanma",
          };
          const limit = toUsageLimit(summary, 0);
          if (limit) {
            limits.push(limit);
          }
        }
      }

      if (Array.isArray(payload.limits)) {
        payload.limits.forEach((item: unknown, idx: number) => {
          if (typeof item !== "object" || item === null || Array.isArray(item)) return;
          const itemRecord = item as KimiLimitItem;
          const detailRecord: KimiUsageDetail =
            typeof itemRecord.detail === "object" && itemRecord.detail !== null && !Array.isArray(itemRecord.detail)
              ? itemRecord.detail
              : (itemRecord as KimiUsageDetail);
          const windowRecord: KimiWindowData =
            typeof itemRecord.window === "object" && itemRecord.window !== null && !Array.isArray(itemRecord.window)
              ? itemRecord.window
              : {};
          const defaultLabel = `Limit #${idx + 1}`;
          const row = buildUsageRow(detailRecord, defaultLabel, nowMs);
          if (row) {
            row.window = buildWindow(windowRecord, nowMs);
            const limit = toUsageLimit(row, limits.length);
            if (limit) {
              if (limits.some(l => l.id === limit.id)) {
                limit.id = `${limit.id}-${idx + 1}`;
              }
              limits.push(limit);
            }
          }
        });
      }
    }

    if (limits.length === 0 && !isExplicitEmptyUsagePayload(rawPayload)) {
      throw new Error(`Kimi Code API geçerli bir kota veya limit verisi döndürmedi. Şema ipucu: ${describeKimiUsageSchema(rawPayload)}`);
    }

    return {
      provider: credential.provider || "kimi-code",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: nowMs,
      limits,
    };
  }
}

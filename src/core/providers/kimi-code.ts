import * as crypto from "node:crypto";
import * as os from "node:os";
import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus, UsageWindow } from "../../types";

const DEFAULT_BASE_URL = "https://api.kimi.com/coding/v1";
const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
const WEEK_MS = 7 * DAY_MS;

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

let cachedDeviceId: string | undefined;

function getKimiHeaders(token: string): Record<string, string> {
  const platform = os.platform();
  const release = os.release();
  const arch = os.arch();
  const osLabel = platform === "darwin" ? "macOS" : platform === "win32" ? "Windows" : platform === "linux" ? "Linux" : platform;
  const deviceModel = `${osLabel} ${release} ${arch}`.replace(/[^\x20-\x7E]/g, "").trim() || "unknown";
  const deviceName = os.hostname().replace(/[^\x20-\x7E]/g, "").trim() || "unknown";
  const osVersion = os.version().replace(/[^\x20-\x7E]/g, "").trim() || "unknown";

  if (!cachedDeviceId) {
    cachedDeviceId = crypto.randomUUID().replace(/-/g, "");
  }

  return {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
    "User-Agent": "KimiCLI/1.0.0",
    "X-Msh-Platform": "kimi_cli",
    "X-Msh-Version": "1.0.0",
    "X-Msh-Device-Name": deviceName,
    "X-Msh-Device-Model": deviceModel,
    "X-Msh-Os-Version": osVersion,
    "X-Msh-Device-Id": cachedDeviceId,
  };
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

    const token = extractBearerToken(credential.secret);
    if (!token) {
      throw new Error("Kimi Code OAuth erişim belirteci (access token) eksik veya boş.");
    }

    if (token.startsWith("sk-") && !token.includes("ey")) {
      throw new Error("Kimi Code kullanım API'si yalnızca OAuth belirteçlerini destekler; standart API anahtarları desteklenmez.");
    }

    const fetchImpl = ctx?.fetch ?? fetch;
    const nowMs = Date.now();
    const envBase = process.env["KIMI_CODE_BASE_URL"]?.trim();
    const baseUrl = envBase ? envBase.replace(/\/+$/, "") : DEFAULT_BASE_URL;
    const url = `${baseUrl}/usages`;

    const response = await fetchImpl(url, {
      method: "GET",
      headers: getKimiHeaders(token),
      signal: ctx?.signal,
    });

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
    const limits: UsageLimit[] = [];

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

    if (limits.length === 0) {
      throw new Error("Kimi Code API geçerli bir kota veya limit verisi döndürmedi.");
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

import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus } from "../../types";

export const ALIBABA_TOKEN_PLAN_PROVIDER = "alibaba-token-plan";
export const ALIBABA_TOKEN_PLAN_BASE_URL = "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1";
export const ALIBABA_TOKEN_PLAN_CN_BASE_URL = "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";

const USAGE_API = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage";
const BROWSER_USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

const HOUR_MS = 60 * 60 * 1000;
const WEEK_MS = 7 * 24 * HOUR_MS;

const INTERNATIONAL_CONSOLE = {
  origin: "https://home.qwencloud.com",
  dashboardUrl: "https://home.qwencloud.com/billing/subscription/token-plan-individual",
  sessionUrl: "https://home.qwencloud.com/tool/user/info.json",
  gatewayAction: "IntlBroadScopeAspnGateway",
  region: "ap-southeast-1",
  usageUrl: `https://cs-data.qwencloud.com/data/api.json?product=sfm_bailian&action=IntlBroadScopeAspnGateway&api=${encodeURIComponent(USAGE_API)}`,
  cornerstoneParam: {
    domain: "home.qwencloud.com",
    consoleSite: "QWENCLOUD",
    console: "ONE_CONSOLE",
    xsp_lang: "en-US",
    protocol: "V2",
    productCode: "p_efm",
  },
} as const;

const CHINA_CONSOLE = {
  origin: "https://bailian.console.aliyun.com",
  dashboardUrl: "https://bailian.console.aliyun.com/cn-beijing?tab=plan",
  sessionUrl: "https://bailian.console.aliyun.com/cn-beijing?tab=plan",
  gatewayAction: "BroadScopeAspnGateway",
  region: "cn-beijing",
  usageUrl: `https://bailian-cs.console.aliyun.com/data/api.json?action=BroadScopeAspnGateway&product=sfm_bailian&api=${encodeURIComponent(USAGE_API)}`,
  cornerstoneParam: {
    feURL: "https://bailian.console.aliyun.com/cn-beijing?tab=plan#/efm/subscription/token-plan/personal",
    protocol: "V2",
    console: "ONE_CONSOLE",
    productCode: "p_efm",
    switchAgent: 12608464,
    switchUserType: 3,
    domain: "bailian.console.aliyun.com",
    consoleSite: "BAILIAN_ALIYUN",
    userNickName: "",
    userPrincipalName: "",
    xsp_lang: "zh-CN",
  },
} as const;

const TOKEN_PATTERN = /^sk-[A-Za-z0-9._~+/-]+={0,2}$/;

export interface AlibabaTokenPlanCredential {
  token?: string;
  cookie?: string;
  baseUrl?: string;
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length === 0) return undefined;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function parseUsedFraction(value: unknown): number | undefined {
  const parsed = toNumber(value);
  if (parsed === undefined || parsed < 0) return undefined;
  return Math.min(1, parsed > 1 ? parsed / 100 : parsed);
}

function parsePositiveTimestamp(value: unknown): number | undefined {
  const num = toNumber(value);
  if (num === undefined || num <= 0) return undefined;
  return num < 100_000_000_000 ? Math.round(num * 1000) : Math.round(num);
}

function extractCookieValue(header: string, name: string): string | undefined {
  for (const segment of header.split(";")) {
    const separator = segment.indexOf("=");
    if (separator < 0 || segment.slice(0, separator).trim() !== name) continue;
    const value = segment.slice(separator + 1).trim();
    if (value.length > 0) return value;
  }
  return undefined;
}

function unwrapGatewayData(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {};
  }

  let current: Record<string, unknown> = { ...(value as Record<string, unknown>) };

  if (typeof current["Data"] === "string") {
    try {
      const parsed: unknown = JSON.parse(current["Data"] as string);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        current = parsed as Record<string, unknown>;
      }
    } catch {
      // Keep existing current
    }
  }

  const dataV2 = current["DataV2"];
  if (typeof dataV2 === "object" && dataV2 !== null && !Array.isArray(dataV2)) {
    const innerData = (dataV2 as Record<string, unknown>)["data"];
    if (typeof innerData === "object" && innerData !== null && !Array.isArray(innerData)) {
      current = innerData as Record<string, unknown>;
    }
  }

  const directData = current["data"];
  if (typeof directData === "object" && directData !== null && !Array.isArray(directData)) {
    current = directData as Record<string, unknown>;
  }

  return current;
}

function parseCredential(secret: string, metadata?: Record<string, unknown>): AlibabaTokenPlanCredential {
  const trimmed = secret.trim();
  let token: string | undefined;
  let cookie: string | undefined;
  let baseUrl: string | undefined;

  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        const obj = parsed as Record<string, unknown>;
        if (typeof obj["token"] === "string" && (obj["token"] as string).trim().length > 0) {
          token = (obj["token"] as string).trim();
        } else if (typeof obj["apiKey"] === "string" && (obj["apiKey"] as string).trim().length > 0) {
          token = (obj["apiKey"] as string).trim();
        } else if (typeof obj["key"] === "string" && (obj["key"] as string).trim().length > 0) {
          token = (obj["key"] as string).trim();
        }

        if (typeof obj["cookie"] === "string" && (obj["cookie"] as string).trim().length > 0) {
          cookie = (obj["cookie"] as string).trim();
        }

        if (typeof obj["baseUrl"] === "string" && (obj["baseUrl"] as string).trim().length > 0) {
          baseUrl = (obj["baseUrl"] as string).trim();
        }
      }
    } catch {
      // Continue to string pattern matching
    }
  }

  if (!token && TOKEN_PATTERN.test(trimmed)) {
    token = trimmed;
  }

  if (!cookie && metadata && typeof metadata["cookie"] === "string" && (metadata["cookie"] as string).trim().length > 0) {
    cookie = (metadata["cookie"] as string).trim();
  }

  if (!baseUrl && metadata && typeof metadata["baseUrl"] === "string" && (metadata["baseUrl"] as string).trim().length > 0) {
    baseUrl = (metadata["baseUrl"] as string).trim();
  }

  if (!cookie && (trimmed.includes("login_aliyunid_csrf") || (trimmed.includes("=") && trimmed.includes(";")))) {
    cookie = trimmed;
  }

  return { token, cookie, baseUrl };
}

function buildLimit(
  id: "5h" | "7d",
  label: string,
  durationMs: number,
  usedFraction: number | undefined,
  resetsAt: number | undefined,
): UsageLimit | undefined {
  if (usedFraction === undefined) return undefined;
  const usedPercent = Math.round(usedFraction * 1000) / 10;
  const status: UsageStatus = usedFraction >= 1 ? "exhausted" : usedFraction >= 0.8 ? "warning" : "ok";

  return {
    id: `credits:${id}`,
    label,
    amount: {
      used: usedPercent,
      limit: 100,
      remaining: Math.max(0, Math.round((100 - usedPercent) * 10) / 10),
      usedFraction,
      unit: "percent",
    },
    window: {
      id,
      label,
      durationMs,
      ...(resetsAt !== undefined ? { resetsAt } : {}),
      resetLabel: "resets",
    },
    status,
  };
}

export class AlibabaTokenPlanAdapter implements ProviderAdapter {
  readonly id = ALIBABA_TOKEN_PLAN_PROVIDER;

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return (
      p === ALIBABA_TOKEN_PLAN_PROVIDER ||
      p === "alibaba_token_plan" ||
      p === "alibabatokenplan" ||
      p === "qwen-token-plan" ||
      p === "qwencloud-token-plan" ||
      p === "bailian-token-plan"
    );
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    if (credential.credentialType === "oauth") {
      throw new Error(
        "Alibaba Token Plan OAuth kimlik doğrulamasını desteklemez. Lütfen API anahtarı ve konsol oturum çerezi (Cookie) kullanın.",
      );
    }

    const rawSecret = credential.secret?.trim();
    if (!rawSecret || rawSecret.length === 0) {
      throw new Error("Alibaba Token Plan kimlik bilgisi boş olamaz.");
    }

    const parsedCred = parseCredential(rawSecret, credential.metadata);

    if (!parsedCred.cookie) {
      throw new Error(
        "Alibaba Token Plan kota sorgulaması için QwenCloud/Bailian konsol oturum çerezi (Cookie) gereklidir. " +
          "API anahtarı tek başına konsol kota sorgulama yetkisine sahip değildir; lütfen Cookie içeren kimlik bilgisi sağlayın.",
      );
    }

    const cookie = parsedCred.cookie.replace(/^Cookie:\s*/i, "").trim();
    const isChina =
      parsedCred.baseUrl === ALIBABA_TOKEN_PLAN_CN_BASE_URL ||
      (typeof parsedCred.baseUrl === "string" && parsedCred.baseUrl.includes("cn-beijing"));
    const consoleConfig = isChina ? CHINA_CONSOLE : INTERNATIONAL_CONSOLE;

    const fetchImpl = ctx?.fetch ?? fetch;

    // 1. Session lookup to retrieve sec_token
    const sessionResponse = await fetchImpl(consoleConfig.sessionUrl, {
      headers: {
        Accept: isChina
          ? "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
          : "application/json, text/plain, */*",
        Cookie: cookie,
        Referer: `${consoleConfig.origin}/`,
        "User-Agent": BROWSER_USER_AGENT,
      },
      redirect: "manual",
      signal: ctx?.signal,
    });

    if (!sessionResponse.ok) {
      throw new Error(
        `Alibaba Token Plan oturum doğrulaması başarısız oldu (HTTP ${sessionResponse.status} ${sessionResponse.statusText}). ` +
          "Oturum çerezi geçersiz veya süresi dolmuş olabilir.",
      );
    }

    let secToken: string | undefined;
    if (isChina) {
      const html = await sessionResponse.text();
      secToken = /\bSEC_TOKEN\s*:\s*"([^"]+)"/.exec(html)?.[1];
      if (!secToken) {
        throw new Error(
          "Alibaba Token Plan Çin konsol oturumunda SEC_TOKEN bulunamadı. Lütfen oturum çerezinizi yenileyin.",
        );
      }
    } else {
      let userPayload: unknown;
      try {
        userPayload = await sessionResponse.json();
      } catch {
        throw new Error("QwenCloud oturum yanıtı geçerli JSON formatında değil.");
      }

      const payloadObj =
        typeof userPayload === "object" && userPayload !== null && !Array.isArray(userPayload)
          ? (userPayload as Record<string, unknown>)
          : undefined;

      const dataObj =
        payloadObj && typeof payloadObj["data"] === "object" && payloadObj["data"] !== null && !Array.isArray(payloadObj["data"])
          ? (payloadObj["data"] as Record<string, unknown>)
          : undefined;

      if (!dataObj || typeof dataObj["secToken"] !== "string" || (dataObj["secToken"] as string).trim().length === 0) {
        throw new Error(
          "QwenCloud oturum yanıtında geçerli secToken bulunamadı. Oturum çerezi geçersiz veya süresi dolmuş olabilir.",
        );
      }
      secToken = dataObj["secToken"] as string;
    }

    // 2. Query Usage API
    const csrf = extractCookieValue(cookie, "login_aliyunid_csrf") ?? extractCookieValue(cookie, "csrf");
    const headers: Record<string, string> = {
      Accept: "application/json, text/plain, */*",
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: cookie,
      Origin: consoleConfig.origin,
      Referer: consoleConfig.dashboardUrl,
      "User-Agent": BROWSER_USER_AGENT,
      "X-Requested-With": "XMLHttpRequest",
    };
    if (csrf) {
      headers["x-xsrf-token"] = csrf;
      headers["x-csrf-token"] = csrf;
    }

    const body = new URLSearchParams({
      product: "sfm_bailian",
      action: consoleConfig.gatewayAction,
      region: consoleConfig.region,
      sec_token: secToken,
      params: JSON.stringify({
        Api: USAGE_API,
        Data: {
          cornerstoneParam: {
            ...(isChina ? { feTraceId: crypto.randomUUID() } : {}),
            ...consoleConfig.cornerstoneParam,
          },
        },
        V: "1.0",
      }),
    });

    const usageResponse = await fetchImpl(consoleConfig.usageUrl, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal: ctx?.signal,
    });

    if (!usageResponse.ok) {
      throw new Error(
        `Alibaba Token Plan kota sorgulaması başarısız oldu: HTTP ${usageResponse.status} ${usageResponse.statusText}`,
      );
    }

    let payload: unknown;
    try {
      payload = await usageResponse.json();
    } catch {
      throw new Error("Alibaba Token Plan kota yanıtı geçerli JSON formatında değil.");
    }

    const isPayloadValidObj = typeof payload === "object" && payload !== null && !Array.isArray(payload);
    const payloadObj = isPayloadValidObj ? (payload as Record<string, unknown>) : undefined;

    if (!payloadObj || payloadObj["successResponse"] === false || typeof payloadObj["data"] !== "object" || payloadObj["data"] === null) {
      const errMsg =
        payloadObj && typeof payloadObj["errorMsg"] === "string" ? `: ${payloadObj["errorMsg"]}` : "";
      throw new Error(`Alibaba Token Plan kota yanıtı geçersiz veya hata döndürdü${errMsg}`);
    }

    const responseData = unwrapGatewayData(payloadObj["data"]);

    const limits = [
      buildLimit(
        "5h",
        "5 Hour Credits",
        5 * HOUR_MS,
        parseUsedFraction(responseData["per5HourPercentage"]),
        parsePositiveTimestamp(responseData["per5HourResetTime"]),
      ),
      buildLimit(
        "7d",
        "7 Day Credits",
        WEEK_MS,
        parseUsedFraction(responseData["per1WeekPercentage"]),
        parsePositiveTimestamp(responseData["per1WeekResetTime"]),
      ),
    ].filter((limit): limit is UsageLimit => limit !== undefined);

    if (limits.length === 0) {
      throw new Error("Alibaba Token Plan kullanım verisinde geçerli kota penceresi bulunamadı.");
    }

    return {
      provider: ALIBABA_TOKEN_PLAN_PROVIDER,
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits,
    };
  }
}

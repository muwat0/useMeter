const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const DEVICE_USERCODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token";

const TOKEN_URL = "https://auth.openai.com/oauth/token";
const DEVICE_REDIRECT_URI = "https://auth.openai.com/deviceauth/callback";
const VERIFICATION_URL = "https://auth.openai.com/codex/device";

export interface CodexDeviceInitiateResult {
  deviceAuthId: string;
  userCode: string;
  verificationUrl: string;
  interval: number;
  expiresIn: number;
}

export interface CodexTokenResult {
  accessToken: string;
  refreshToken?: string;
  email?: string;
  accountId?: string;
  planType?: string;
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[1]) return null;
    const decoded = Buffer.from(parts[1], "base64").toString("utf-8");
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function initiateCodexDeviceAuth(signal?: AbortSignal): Promise<CodexDeviceInitiateResult> {
  const res = await fetch(DEVICE_USERCODE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: CLIENT_ID }),
    signal,
  });

  if (!res.ok) {
    throw new Error(`OpenAI cihaz yetkilendirmesi başlatılamadı: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    device_auth_id?: string;
    user_code?: string;
    interval?: number | string;
    expires_in?: number | string;
  };

  if (!data.device_auth_id || !data.user_code) {
    throw new Error("OpenAI geçersiz cihaz kodu yanıtı döndü.");
  }

  const interval = typeof data.interval === "number" ? data.interval : parseInt(String(data.interval ?? "5"), 10) || 5;

  const parsedExpiresIn =
    typeof data.expires_in === "number"
      ? data.expires_in
      : parseInt(String(data.expires_in ?? ""), 10);
  const expiresIn = Number.isFinite(parsedExpiresIn) && parsedExpiresIn > 0 ? parsedExpiresIn : 900;

  return {
    deviceAuthId: data.device_auth_id,
    userCode: data.user_code,
    verificationUrl: VERIFICATION_URL,
    interval,
    expiresIn,
  };
}

export type PollResult =
  | { status: "pending" }
  | { status: "complete"; authorizationCode: string; codeVerifier: string }
  | { status: "error"; message: string };

export async function pollCodexDeviceAuth(deviceAuthId: string, userCode: string, signal?: AbortSignal): Promise<PollResult> {
  const res = await fetch(DEVICE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_auth_id: deviceAuthId,
      user_code: userCode,
    }),
    signal,
  });

  // 403 / 404 = user hasn't approved yet
  if (res.status === 403 || res.status === 404) {
    return { status: "pending" };
  }

  if (!res.ok) {
    return { status: "error", message: `Sorgu hatası: HTTP ${res.status}` };
  }

  const data = (await res.json()) as {
    authorization_code?: string;
    code_verifier?: string;
  };

  if (!data.authorization_code || !data.code_verifier) {
    return { status: "error", message: "Onay kodu eksik döndü." };
  }

  return {
    status: "complete",
    authorizationCode: data.authorization_code,
    codeVerifier: data.code_verifier,
  };
}

export async function exchangeCodexToken(
  authorizationCode: string,
  codeVerifier: string,
  signal?: AbortSignal,
): Promise<CodexTokenResult> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      grant_type: "authorization_code",
      code: authorizationCode,
      code_verifier: codeVerifier,
      redirect_uri: DEVICE_REDIRECT_URI,
    }),
    signal,
  });

  if (!res.ok) {
    throw new Error(`Token değişimi başarısız: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    id_token?: string;
  };

  if (!data.access_token) {
    throw new Error("Erişim token'ı alınamadı.");
  }

  const jwt = decodeJwtPayload(data.access_token);
  const idJwt = data.id_token ? decodeJwtPayload(data.id_token) : null;

  const authClaim = jwt?.["https://api.openai.com/auth"] as Record<string, unknown> | undefined;
  const profileClaim = jwt?.["https://api.openai.com/profile"] as Record<string, unknown> | undefined;
  const idAuthClaim = idJwt?.["https://api.openai.com/auth"] as Record<string, unknown> | undefined;

  const accountId = typeof authClaim?.["chatgpt_account_id"] === "string" ? authClaim["chatgpt_account_id"] : undefined;
  const email = typeof profileClaim?.["email"] === "string" ? profileClaim["email"] : undefined;
  const planType = typeof (authClaim?.["chatgpt_plan_type"] ?? idAuthClaim?.["chatgpt_plan_type"]) === "string"
    ? String(authClaim?.["chatgpt_plan_type"] ?? idAuthClaim?.["chatgpt_plan_type"])
    : undefined;

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    email,
    accountId,
    planType,
  };
}

export async function refreshCodexToken(
  refreshToken: string,
  context?: { fetch?: typeof fetch; signal?: AbortSignal },
): Promise<CodexTokenResult> {
  const fetchImpl = context?.fetch ?? fetch;
  const res = await fetchImpl(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }),
    signal: context?.signal,
  });

  if (!res.ok) {
    throw new Error(`Codex token refresh failed: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
  };
  if (!data.access_token) {
    throw new Error("Codex refreshed access token missing.");
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
  };
}

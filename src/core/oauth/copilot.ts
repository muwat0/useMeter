const CLIENT_ID = "Ov23li8tweQw6odWQebz";
const DEVICE_CODE_URL = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";

export interface CopilotDeviceInitiateResult {
  deviceCode: string;
  userCode: string;
  verificationUrl: string;
  interval: number;
  expiresIn: number;
}

export interface CopilotTokenResult {
  accessToken: string;
  login?: string;
  email?: string;
}

export type CopilotPollResult =
  | { status: "pending" }
  | { status: "slow_down"; interval?: number }
  | { status: "complete"; token: CopilotTokenResult }
  | { status: "error"; message: string };

export async function initiateCopilotDeviceAuth(): Promise<CopilotDeviceInitiateResult> {
  const res = await fetch(DEVICE_CODE_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "opencode/1.3.15",
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      scope: "read:user",
    }),
  });

  if (!res.ok) {
    throw new Error(`GitHub Copilot cihaz yetkilendirmesi başlatılamadı: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    device_code?: string;
    user_code?: string;
    verification_uri?: string;
    interval?: number;
    expires_in?: number;
  };

  if (!data.device_code || !data.user_code || !data.verification_uri) {
    throw new Error("GitHub Copilot geçersiz cihaz kodu yanıtı döndü.");
  }

  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUrl: data.verification_uri,
    interval: data.interval ?? 5,
    expiresIn: data.expires_in ?? 900,
  };
}

export async function pollCopilotDeviceAuth(deviceCode: string): Promise<CopilotPollResult> {
  const res = await fetch(ACCESS_TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "opencode/1.3.15",
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      device_code: deviceCode,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    }),
  });

  if (!res.ok) {
    return { status: "error", message: `Sorgu hatası: HTTP ${res.status}` };
  }

  const data = (await res.json()) as {
    access_token?: string;
    error?: string;
    error_description?: string;
    interval?: number;
  };

  if (data.error === "authorization_pending") {
    return { status: "pending" };
  }

  if (data.error === "slow_down") {
    return { status: "slow_down", interval: data.interval };
  }

  if (data.error) {
    return { status: "error", message: data.error_description || data.error };
  }

  if (!data.access_token) {
    return { status: "error", message: "Erişim token'ı alınamadı." };
  }

  let login: string | undefined;
  let email: string | undefined;
  try {
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${data.access_token}`,
        "User-Agent": "GitHubCopilotChat/0.26.7",
        Accept: "application/json",
      },
    });
    if (userRes.ok) {
      const u = (await userRes.json()) as { login?: string; email?: string };
      login = u.login;
      email = u.email;
    }
  } catch {}

  return {
    status: "complete",
    token: {
      accessToken: data.access_token,
      login,
      email,
    },
  };
}

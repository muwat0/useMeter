const XAI_OAUTH_ISSUER = "https://auth.x.ai";
const XAI_OAUTH_DEVICE_CODE_URL = `${XAI_OAUTH_ISSUER}/oauth2/device/code`;
const XAI_OAUTH_TOKEN_URL = `${XAI_OAUTH_ISSUER}/oauth2/token`;
const XAI_OAUTH_USERINFO_URL = `${XAI_OAUTH_ISSUER}/oauth2/userinfo`;
const XAI_OAUTH_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_OAUTH_SCOPE = "openid profile email offline_access grok-cli:access api:access";

export interface XaiDeviceInitiateResult {
  deviceCode: string;
  userCode: string;
  verificationUrl: string;
  interval: number;
  expiresIn: number;
}

export type XaiPollResult =
  | { status: "pending" }
  | { status: "slow_down"; interval?: number }
  | { status: "complete"; accessToken: string; refreshToken?: string; email?: string }
  | { status: "error"; message: string };

export async function initiateXaiDeviceAuth(): Promise<XaiDeviceInitiateResult> {
  const res = await fetch(XAI_OAUTH_DEVICE_CODE_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: XAI_OAUTH_CLIENT_ID,
      scope: XAI_OAUTH_SCOPE,
    }).toString(),
  });

  if (!res.ok) {
    throw new Error(`xAI device auth failed: ${res.status} ${await res.text()}`);
  }

  const data = (await res.json()) as {
    device_code?: string;
    user_code?: string;
    verification_uri?: string;
    verification_uri_complete?: string;
    expires_in?: number;
    interval?: number;
  };

  if (!data.device_code || !data.user_code) {
    throw new Error("xAI invalid device code response");
  }

  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUrl: data.verification_uri_complete || data.verification_uri || "https://accounts.x.ai/oauth2/device",
    interval: data.interval ?? 5,
    expiresIn: data.expires_in ?? 300,
  };
}

export async function pollXaiDeviceAuth(deviceCode: string): Promise<XaiPollResult> {
  const res = await fetch(XAI_OAUTH_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: XAI_OAUTH_CLIENT_ID,
      device_code: deviceCode,
    }).toString(),
  });

  const data = (await res.json().catch(() => ({}))) as {
    access_token?: string;
    refresh_token?: string;
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
  if (!res.ok || data.error) {
    return { status: "error", message: data.error_description || data.error || `HTTP ${res.status}` };
  }

  let email: string | undefined;
  if (data.access_token) {
    try {
      const uRes = await fetch(XAI_OAUTH_USERINFO_URL, {
        headers: { Authorization: `Bearer ${data.access_token}`, Accept: "application/json" },
      });
      if (uRes.ok) {
        const u = (await uRes.json()) as { email?: string };
        email = u.email;
      }
    } catch {}
  }

  return {
    status: "complete",
    accessToken: data.access_token!,
    refreshToken: data.refresh_token,
    email,
  };
}

export async function refreshXaiToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
  const res = await fetch(XAI_OAUTH_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: XAI_OAUTH_CLIENT_ID,
      refresh_token: refreshToken,
    }).toString(),
  });

  if (!res.ok) {
    throw new Error(`xAI token refresh failed: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
  };

  if (!data.access_token) {
    throw new Error("xAI refreshed access token missing.");
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || refreshToken,
  };
}

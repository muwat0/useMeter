import * as crypto from "node:crypto";
import * as os from "node:os";

const CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098";
const DEFAULT_OAUTH_HOST = "https://auth.kimi.com";

function getKimiHeaders(deviceId: string) {
  return {
    "User-Agent": "KimiCLI/0.2.148",
    "X-Msh-Platform": "kimi_cli",
    "X-Msh-Version": "0.2.148",
    "X-Msh-Device-Name": os.hostname(),
    "X-Msh-Device-Model": os.platform(),
    "X-Msh-Os-Version": os.version(),
    "X-Msh-Device-Id": deviceId,
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
}

export interface KimiDeviceInitiateResult {
  deviceCode: string;
  userCode: string;
  verificationUrl: string;
  interval: number;
  expiresIn: number;
  deviceId: string;
}

export type KimiPollResult =
  | { status: "pending" }
  | { status: "slow_down"; interval?: number }
  | { status: "complete"; accessToken: string; refreshToken?: string; accountId?: string }
  | { status: "error"; message: string };

export async function initiateKimiDeviceAuth(signal?: AbortSignal): Promise<KimiDeviceInitiateResult> {
  const deviceId = crypto.randomUUID().replace(/-/g, "");
  const res = await fetch(`${DEFAULT_OAUTH_HOST}/api/oauth/device_authorization`, {
    method: "POST",
    headers: getKimiHeaders(deviceId),
    body: new URLSearchParams({ client_id: CLIENT_ID }).toString(),
    signal,
  });

  if (!res.ok) {
    throw new Error(`Kimi device auth failed: ${res.status} ${await res.text()}`);
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
    throw new Error("Kimi invalid device code response");
  }

  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUrl: data.verification_uri_complete || data.verification_uri || "https://www.kimi.com/code/authorize_device",
    interval: data.interval ?? 5,
    expiresIn: data.expires_in ?? 900,
    deviceId,
  };
}

export async function pollKimiDeviceAuth(deviceCode: string, deviceId: string, signal?: AbortSignal): Promise<KimiPollResult> {
  const res = await fetch(`${DEFAULT_OAUTH_HOST}/api/oauth/token`, {
    method: "POST",
    headers: getKimiHeaders(deviceId || crypto.randomUUID().replace(/-/g, "")),
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      device_code: deviceCode,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    }).toString(),
    signal,
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

  let accountId: string | undefined;
  if (data.access_token) {
    try {
      const parts = data.access_token.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        accountId = payload.user_id || payload.sub;
      }
    } catch {}
  }

  return {
    status: "complete",
    accessToken: data.access_token!,
    refreshToken: data.refresh_token,
    accountId,
  };
}

export async function refreshKimiToken(refreshToken: string, deviceId?: string): Promise<{ accessToken: string; refreshToken: string }> {
  const did = deviceId || crypto.randomUUID().replace(/-/g, "");
  const res = await fetch(`${DEFAULT_OAUTH_HOST}/api/oauth/token`, {
    method: "POST",
    headers: getKimiHeaders(did),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
  });

  if (!res.ok) {
    throw new Error(`Kimi token refresh failed: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
  };

  if (!data.access_token) {
    throw new Error("Kimi refreshed access token missing.");
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || refreshToken,
  };
}

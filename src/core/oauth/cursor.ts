import { generatePKCE } from "./pkce";

const CURSOR_LOGIN_URL = "https://cursor.com/loginDeepControl";
const CURSOR_POLL_URL = "https://api2.cursor.sh/auth/poll";
const CURSOR_REFRESH_URL = "https://api2.cursor.sh/auth/exchange_user_api_key";

export interface CursorAuthInitiateResult {
  authUrl: string;
  uuid: string;
  verifier: string;
  interval: number;
  expiresIn?: number;
}

export type CursorPollResult =
  | { status: "pending" }
  | { status: "complete"; accessToken: string; refreshToken: string; email?: string }
  | { status: "error"; message: string };

export async function initiateCursorAuth(): Promise<CursorAuthInitiateResult> {
  const { verifier, challenge } = generatePKCE();
  const uuid = crypto.randomUUID();

  const params = new URLSearchParams({
    challenge,
    uuid,
    mode: "login",
    redirectTarget: "cli",
  });

  return {
    authUrl: `${CURSOR_LOGIN_URL}?${params.toString()}`,
    uuid,
    verifier,
    interval: 2,
    expiresIn: 600,
  };
}

export async function pollCursorAuth(uuid: string, verifier: string, signal?: AbortSignal): Promise<CursorPollResult> {
  try {
    const res = await fetch(`${CURSOR_POLL_URL}?uuid=${uuid}&verifier=${verifier}`, {
      headers: { Accept: "application/json" },
      signal,
    });

    if (res.status === 404) {
      return { status: "pending" };
    }

    if (!res.ok) {
      return { status: "error", message: `Cursor poll failed: HTTP ${res.status}` };
    }

    const data = (await res.json()) as {
      accessToken?: string;
      refreshToken?: string;
    };

    if (!data.accessToken) {
      return { status: "error", message: "Cursor yanıtında access token bulunamadı." };
    }

    let email: string | undefined;
    try {
      const parts = data.accessToken.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { sub?: string; email?: string };
        if (typeof payload.email === "string" && payload.email.trim()) {
          email = payload.email.trim();
        } else if (typeof payload.sub === "string" && payload.sub.trim()) {
          const subParts = payload.sub.trim().split("|");
          const userId = subParts.length > 1 ? subParts[1] : payload.sub.trim();
          const meRes = await fetch("https://cursor.com/api/auth/me", {
            headers: {
              Accept: "application/json",
              Cookie: `WorkosCursorSessionToken=${encodeURIComponent(`${userId}::${data.accessToken}`)}`,
              "User-Agent": "Cursor/0.46.1",
            },
            signal,
          });
          if (meRes.ok) {
            const meJson = (await meRes.json()) as { email?: string };
            if (typeof meJson.email === "string" && meJson.email.trim()) {
              email = meJson.email.trim();
            }
          }
        }
      }
    } catch {}
    return {
      status: "complete",
      accessToken: data.accessToken,
      refreshToken: data.refreshToken || "",
      email,
    };
  } catch (err) {
    return { status: "error", message: String(err) };
  }
}

export async function refreshCursorToken(apiKeyOrRefreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
  const res = await fetch(CURSOR_REFRESH_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKeyOrRefreshToken}`,
      "Content-Type": "application/json",
    },
    body: "{}",
  });

  if (!res.ok) {
    throw new Error(`Cursor token refresh failed: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    accessToken: string;
    refreshToken: string;
  };

  return {
    access: data.accessToken,
    refresh: data.refreshToken || apiKeyOrRefreshToken,
  } as any;
}

import { listenForOAuthCallback } from "./callback-server";

const CLIENT_ID = Buffer.from(
  "NjgxMjU1ODA5Mzk1LW9vOGZ0Mm9wcmRybnA5ZTNhcWY2YXYzaG1kaWIxMzVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t",
  "base64"
).toString("utf-8");
const CLIENT_SECRET = Buffer.from(
  "R09DU1BYLTR1SGdNUG0tMW83U2stZ2VWNkN1NWNsWEZzeGw=",
  "base64"
).toString("utf-8");

const CALLBACK_PORT = 8085;
const CALLBACK_PATH = "/oauth2callback";
const REDIRECT_URI = `http://127.0.0.1:${CALLBACK_PORT}${CALLBACK_PATH}`;
const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com";
const SCOPES = [
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
].join(" ");

export interface GeminiCliAuthInitiateResult {
  authUrl: string;
  state: string;
}

export interface GeminiCliTokenResult {
  accessToken: string;
  refreshToken?: string;
  email?: string;
  projectId?: string;
}

export function initiateGeminiCliAuth(): GeminiCliAuthInitiateResult {
  const state = Math.random().toString(36).substring(2);

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state,
    access_type: "offline",
    prompt: "consent",
  });

  return {
    authUrl: `${AUTH_URL}?${params.toString()}`,
    state,
  };
}

export async function listenForGeminiCliCallback(
  expectedState: string,
  timeoutMs: number = 120_000,
  signal?: AbortSignal,
): Promise<string> {
  return listenForOAuthCallback({
    port: CALLBACK_PORT,
    pathname: CALLBACK_PATH,
    expectedState,
    providerName: "Gemini CLI",
    timeoutMs,
    signal,
  });
}

export async function exchangeGeminiCliCode(code: string, signal?: AbortSignal): Promise<GeminiCliTokenResult> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI,
    }).toString(),
    signal,
  });

  if (!res.ok) {
    throw new Error(`Gemini CLI token değişimi başarısız: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
  };

  if (!data.access_token) {
    throw new Error("Gemini CLI access token alınamadı.");
  }

  let email: string | undefined;
  try {
    const userRes = await fetch("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", {
      headers: { Authorization: `Bearer ${data.access_token}` },
      signal,
    });
    if (userRes.ok) {
      const u = (await userRes.json()) as { email?: string };
      email = u.email;
    }
  } catch {}

  let projectId = "aicode-consumers";
  try {
    const loadRes = await fetch(`${CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${data.access_token}`,
        "Content-Type": "application/json",
        "User-Agent": "GeminiCLI/0.46.0/gemini-3.1-pro-preview (linux; x64; terminal)",
        "Client-Metadata": "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI",
      },
      body: JSON.stringify({
        metadata: {
          ideType: "IDE_UNSPECIFIED",
          platform: "PLATFORM_UNSPECIFIED",
          pluginType: "GEMINI",
        },
      }),
      signal,
    });
    if (loadRes.ok) {
      const pData = (await loadRes.json()) as { cloudaicompanionProject?: string | { id?: string } };
      if (typeof pData.cloudaicompanionProject === "string") {
        projectId = pData.cloudaicompanionProject;
      } else if (pData.cloudaicompanionProject && typeof pData.cloudaicompanionProject.id === "string") {
        projectId = pData.cloudaicompanionProject.id;
      }
    }
  } catch {}

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    email,
    projectId,
  };
}

export async function refreshGeminiCliToken(refreshToken: string): Promise<string> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }).toString(),
  });

  if (!res.ok) {
    throw new Error(`Gemini CLI token yenileme başarısız: HTTP ${res.status}`);
  }

  const json = (await res.json()) as { access_token?: string };
  if (!json.access_token) {
    throw new Error("Yenilenen access_token alınamadı.");
  }
  return json.access_token;
}

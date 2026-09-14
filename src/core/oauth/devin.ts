import { generatePKCE } from "./pkce";
import { listenForOAuthCallback } from "./callback-server";

const DEVIN_WEBAPP_URL = "https://app.devin.ai";
const DEVIN_API_URL = "https://api.devin.ai";
const CALLBACK_PORT = 59653;
const CALLBACK_PATH = "/callback";
const REDIRECT_URI = `http://127.0.0.1:${CALLBACK_PORT}${CALLBACK_PATH}`;
const TOKEN_PATH = "/auth/cli/token";

export interface DevinAuthInitiateResult {
  authUrl: string;
  verifier: string;
  state: string;
  sessionId: string;
}

export function initiateDevinAuth(): DevinAuthInitiateResult {
  const { verifier, challenge } = generatePKCE();
  const state = Math.random().toString(36).substring(2);

  const params = new URLSearchParams({
    redirect_uri: REDIRECT_URI,
    state,
    prompt: "select_account",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  return {
    authUrl: `${DEVIN_WEBAPP_URL}/auth/cli/continue?${params.toString()}`,
    verifier,
    state,
    sessionId: state,
  };
}

export async function listenForDevinCallback(expectedState: string, timeoutMs: number = 120_000): Promise<string> {
  return listenForOAuthCallback({
    port: CALLBACK_PORT,
    pathname: CALLBACK_PATH,
    expectedState,
    providerName: "Devin",
    timeoutMs,
  });
}

export async function exchangeDevinCode(code: string, verifier: string): Promise<{ token: string; email?: string }> {
  const res = await fetch(`${DEVIN_API_URL}${TOKEN_PATH}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      code,
      code_verifier: verifier,
    }),
  });

  if (!res.ok) {
    const errorText = await res.text().catch(() => "");
    throw new Error(`Devin token exchange failed: HTTP ${res.status} ${errorText}`.trim());
  }

  const data = (await res.json()) as { token?: string };
  if (!data.token) {
    throw new Error("Devin token exchange returned an empty token");
  }

  let email: string | undefined;
  try {
    const [, payload] = data.token.split(".");
    if (payload) {
      const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      email = decoded.email || decoded.user_email || decoded.sub;
    }
  } catch {}

  return { token: data.token, email };
}

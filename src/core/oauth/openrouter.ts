import { generatePKCE } from "./pkce";
import { listenForOAuthCallback } from "./callback-server";

const AUTHORIZE_URL = "https://openrouter.ai/auth";
const KEY_EXCHANGE_URL = "https://openrouter.ai/api/v1/auth/keys";
const KEY_INFO_URL = "https://openrouter.ai/api/v1/auth/key";
const CALLBACK_PORT = 54549;
const CALLBACK_PATH = "/callback";
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}${CALLBACK_PATH}`;

export interface OpenRouterAuthInitiateResult {
  authUrl: string;
  verifier: string;
  sessionId: string;
}

export function initiateOpenRouterAuth(): OpenRouterAuthInitiateResult {
  const { verifier, challenge } = generatePKCE();
  const sessionId = Math.random().toString(36).substring(2);

  const params = new URLSearchParams({
    callback_url: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  return {
    authUrl: `${AUTHORIZE_URL}?${params.toString()}`,
    verifier,
    sessionId,
  };
}

export async function listenForOpenRouterCallback(timeoutMs: number = 120_000): Promise<string> {
  return listenForOAuthCallback({
    port: CALLBACK_PORT,
    pathname: CALLBACK_PATH,
    providerName: "OpenRouter",
    timeoutMs,
  });
}

export async function exchangeOpenRouterCode(code: string, verifier: string): Promise<{ apiKey: string; label?: string }> {
  const res = await fetch(KEY_EXCHANGE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, code_verifier: verifier, code_challenge_method: "S256" }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`OpenRouter key exchange failed: HTTP ${res.status} ${detail}`);
  }

  const data = (await res.json()) as { key?: string };
  if (!data.key) {
    throw new Error("OpenRouter key exchange returned an empty key");
  }

  let label: string | undefined;
  try {
    const infoRes = await fetch(KEY_INFO_URL, {
      headers: { Authorization: `Bearer ${data.key}` },
    });
    if (infoRes.ok) {
      const info = (await infoRes.json()) as { data?: { label?: string } };
      label = info.data?.label;
    }
  } catch {}

  return { apiKey: data.key, label };
}

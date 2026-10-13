import { randomUUID } from "node:crypto";
import { generatePKCE } from "./pkce";
const AUTHORIZE_URL = "https://openrouter.ai/auth";
const KEY_EXCHANGE_URL = "https://openrouter.ai/api/v1/auth/keys";
const KEY_INFO_URL = "https://openrouter.ai/api/v1/auth/key";

export interface OpenRouterAuthInitiateResult {
  authUrl: string;
  verifier: string;
  sessionId: string;
}

export function initiateOpenRouterAuth(): OpenRouterAuthInitiateResult {
  const { verifier, challenge } = generatePKCE();
  const sessionId = randomUUID();

  const params = new URLSearchParams({
    code_challenge: challenge,
    code_challenge_method: "S256",
    key_label: "useMeter",
  });

  return {
    authUrl: `${AUTHORIZE_URL}?${params.toString()}`,
    verifier,
    sessionId,
  };
}


export async function exchangeOpenRouterCode(
  code: string,
  verifier: string,
  signal?: AbortSignal,
): Promise<{ apiKey: string; label?: string }> {
  const res = await fetch(KEY_EXCHANGE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, code_verifier: verifier, code_challenge_method: "S256" }),
    signal,
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
      signal,
    });
    if (infoRes.ok) {
      const info = (await infoRes.json()) as { data?: { label?: string } };
      label = info.data?.label;
    }
  } catch {}

  return { apiKey: data.key, label };
}

import { randomUUID } from "node:crypto";
import { generatePKCE } from "./pkce";
import { listenForOAuthCallback } from "./callback-server";

const DEVIN_WEBAPP_URL = "https://app.devin.ai";
const DEVIN_API_URL = "https://api.devin.ai";
export const DEVIN_CALLBACK_PORT = 59653;
export const DEVIN_CALLBACK_PATH = "/callback";
export const DEVIN_LOCAL_REDIRECT_URI = `http://127.0.0.1:${DEVIN_CALLBACK_PORT}${DEVIN_CALLBACK_PATH}`;
const TOKEN_PATH = "/auth/cli/token";

export interface DevinAuthInitiateResult {
  authUrl: string;
  verifier: string;
  state: string;
  sessionId: string;
  redirectUri: string;
  isHosted: boolean;
}

export function isDevinHostedFlow(): boolean {
  const envUri = process.env["DEVIN_OAUTH_REDIRECT_URI"]?.trim();
  if (envUri) {
    try {
      const url = new URL(envUri);
      const host = url.hostname.toLowerCase();
      const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
      return !isLoopback;
    } catch {
      return false;
    }
  }
  return false;
}

export function getDevinRedirectUri(): string {
  const envUri = process.env["DEVIN_OAUTH_REDIRECT_URI"]?.trim();
  if (envUri) {
    try {
      const parsed = new URL(envUri);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error("must use HTTPS, or HTTP for a local loopback address.");
      }
      if (parsed.username || parsed.password || /^https?:\/\/[^/?#]*@/i.test(envUri)) {
        throw new Error("must not contain userinfo.");
      }
      if (parsed.hash || envUri.includes("#")) {
        throw new Error("must not contain a hash or fragment.");
      }
      if (parsed.search || envUri.includes("?")) {
        throw new Error("must not contain a query string.");
      }

      const host = parsed.hostname.toLowerCase();
      const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
      if (process.env["NODE_ENV"] === "production" && isLoopback) {
        throw new Error("loopback redirect URIs are not allowed in production.");
      }
      if (isLoopback && envUri !== DEVIN_LOCAL_REDIRECT_URI) {
        throw new Error("loopback redirect URI must exactly match the local callback listener.");
      }
      if (!isLoopback) {
        if (parsed.protocol !== "https:") {
          throw new Error("hosted redirect URIs must use HTTPS.");
        }
        if (parsed.pathname !== "/api/oauth/devin/callback") {
          throw new Error("hosted redirect URI path must be exactly '/api/oauth/devin/callback'.");
        }
      }
      return envUri;
    } catch (err) {
      const detail = err instanceof Error ? err.message : "invalid URI.";
      throw new Error(`Invalid DEVIN_OAUTH_REDIRECT_URI: ${detail}`);
    }
  }

  if (process.env["NODE_ENV"] === "production") {
    throw new Error(
      "DEVIN_OAUTH_REDIRECT_URI is not configured. In hosted environments, set it to https://<host>/api/oauth/devin/callback",
    );
  }

  return DEVIN_LOCAL_REDIRECT_URI;
}
export function initiateDevinAuth(): DevinAuthInitiateResult {
  const { verifier, challenge } = generatePKCE();
  const state = randomUUID();
  const redirectUri = getDevinRedirectUri();
  const isHosted = isDevinHostedFlow();

  const params = new URLSearchParams({
    redirect_uri: redirectUri,
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
    redirectUri,
    isHosted,
  };
}

export async function listenForDevinCallback(
  expectedState: string,
  timeoutMs: number = 120_000,
  signal?: AbortSignal,
): Promise<string> {
  return listenForOAuthCallback({
    port: DEVIN_CALLBACK_PORT,
    pathname: DEVIN_CALLBACK_PATH,
    expectedState,
    providerName: "Devin",
    timeoutMs,
    signal,
  });
}

export async function exchangeDevinCode(
  code: string,
  verifier: string,
  signal?: AbortSignal,
): Promise<{ token: string; email?: string }> {
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
    signal,
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

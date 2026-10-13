import { randomUUID } from "node:crypto";
import { generatePKCE } from "./pkce";
import { CLAUDE_REDIRECT_URI } from "./manual-callback";
const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const AUTH_URL = "https://claude.ai/oauth/authorize";
const TOKEN_URL = "https://api.anthropic.com/v1/oauth/token";
const SCOPES = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

export interface ClaudeAuthInitiateResult {
  authUrl: string;
  verifier: string;
  state: string;
  redirectUri: string;
}

export interface ClaudeTokenResult {
  accessToken: string;
  refreshToken?: string;
  accountEmail?: string;
}

export function initiateClaudeAuth(): ClaudeAuthInitiateResult {
  const pkce = generatePKCE();
  const state = randomUUID();

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: CLAUDE_REDIRECT_URI,
    scope: SCOPES,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    state,
  });

  return {
    authUrl: `${AUTH_URL}?${params.toString()}`,
    verifier: pkce.verifier,
    state,
    redirectUri: CLAUDE_REDIRECT_URI,
  };
}

export async function exchangeClaudeCode(
  code: string,
  verifier: string,
  signal?: AbortSignal,
): Promise<ClaudeTokenResult> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: CLAUDE_REDIRECT_URI,
    }),
    signal,
  });

  if (!res.ok) {
    throw new Error(`Claude token değişimi başarısız: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
  };

  if (!data.access_token) {
    throw new Error("Claude access token alınamadı.");
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
  };
}


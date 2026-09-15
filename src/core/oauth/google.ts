import { generatePKCE } from "./pkce";
import { listenForOAuthCallback } from "./callback-server";
const CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const CLIENT_SECRET = "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";
const REDIRECT_URI = process.env["GOOGLE_OAUTH_REDIRECT_URI"] ?? "http://127.0.0.1:51121/oauth-callback";
const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const SCOPES = [
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
].join(" ");

export interface GoogleAuthInitiateResult {
  authUrl: string;
  verifier: string;
  state: string;
}

export function getGoogleRedirectUri(): string {
  return REDIRECT_URI;
}

export interface GoogleTokenResult {
  accessToken: string;
  refreshToken?: string;
  email?: string;
}

export function initiateGoogleAuth(): GoogleAuthInitiateResult {
  const pkce = generatePKCE();
  const state = Math.random().toString(36).substring(2);

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    state,
    access_type: "offline",
    prompt: "consent",
  });

  return {
    authUrl: `${AUTH_URL}?${params.toString()}`,
    verifier: pkce.verifier,
    state,
  };
}

export async function exchangeGoogleCode(code: string, verifier: string): Promise<GoogleTokenResult> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI,
    }).toString(),
  });

  if (!res.ok) {
    throw new Error(`Google token değişimi başarısız: HTTP ${res.status}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
  };

  if (!data.access_token) {
    throw new Error("Google access token alınamadı.");
  }

  // Fetch email
  let email: string | undefined;
  try {
    const userRes = await fetch("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", {
      headers: { Authorization: `Bearer ${data.access_token}` },
    });
    if (userRes.ok) {
      const u = (await userRes.json()) as { email?: string };
      email = u.email;
    }
  } catch {}

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    email,
  };
}

export async function listenForGoogleCallback(
  expectedState: string,
  timeoutMs: number = 120_000,
): Promise<string> {
  return listenForOAuthCallback({
    port: 51121,
    pathname: "/oauth-callback",
    expectedState,
    providerName: "Google",
    timeoutMs,
  });
}

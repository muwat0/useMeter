import { randomUUID } from "node:crypto";
import { generatePKCE } from "./pkce";
import { GOOGLE_EMBEDDED_REDIRECT_URI } from "./manual-callback";
const LEGACY_CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const LEGACY_CLIENT_SECRET = "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";
const DEFAULT_LOCAL_REDIRECT_URI = GOOGLE_EMBEDDED_REDIRECT_URI;
const PUBLIC_CALLBACK_PATH = "/api/oauth/google/callback";
const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const SCOPES = [
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
].join(" ");

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  isCustomClient: boolean;
}

export function isLoopbackRedirectUri(uriString: string): boolean {
  try {
    const url = new URL(uriString);
    const host = url.hostname.toLowerCase();
    return (
      url.protocol === "http:" &&
      (host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]")
    );
  } catch {
    return false;
  }
}

function getConfiguredGoogleOAuthClient(overrides?: Partial<GoogleOAuthConfig>) {
  const envClientId = process.env["GOOGLE_OAUTH_CLIENT_ID"]?.trim();
  const envClientSecret = process.env["GOOGLE_OAUTH_CLIENT_SECRET"]?.trim();
  const clientId = overrides?.clientId?.trim() || envClientId;
  const clientSecret = overrides?.clientSecret?.trim() || envClientSecret;

  if (Boolean(clientId) !== Boolean(clientSecret)) {
    throw new Error(
      "GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET must both be provided together.",
    );
  }

  const resolvedClientId = clientId || LEGACY_CLIENT_ID;
  const resolvedClientSecret = clientSecret || LEGACY_CLIENT_SECRET;
  return {
    clientId: resolvedClientId,
    clientSecret: resolvedClientSecret,
    isCustomClient: Boolean(
      clientId &&
      clientSecret &&
      clientId !== LEGACY_CLIENT_ID &&
      clientSecret !== LEGACY_CLIENT_SECRET,
    ),
    hasConfiguredCredentials: Boolean(clientId || clientSecret),
  };
}

export function getGoogleOAuthClientCredentials(
  overrides?: Pick<GoogleOAuthConfig, "clientId" | "clientSecret">,
): Pick<GoogleOAuthConfig, "clientId" | "clientSecret"> {
  const { clientId, clientSecret } = getConfiguredGoogleOAuthClient(overrides);
  return { clientId, clientSecret };
}
export function getEmbeddedGoogleOAuthClientCredentials(): Pick<
  GoogleOAuthConfig,
  "clientId" | "clientSecret"
> {
  return { clientId: LEGACY_CLIENT_ID, clientSecret: LEGACY_CLIENT_SECRET };
}

function isExactPublicCallbackUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    const authority = uri.slice(uri.indexOf("://") + 3).split(/[/?#]/, 1)[0] || "";
    return (
      parsed.protocol === "https:" &&
      parsed.pathname === PUBLIC_CALLBACK_PATH &&
      parsed.search === "" &&
      parsed.hash === "" &&
      !authority.includes("@") &&
      !uri.includes("?") &&
      !uri.includes("#")
    );
  } catch {
    return false;
  }
}

export function getGoogleOAuthConfig(overrides?: Partial<GoogleOAuthConfig>): GoogleOAuthConfig {
  const client = getConfiguredGoogleOAuthClient(overrides);
  const overrideRedirectUri = overrides?.redirectUri?.trim();
  const envRedirectUri = process.env["GOOGLE_OAUTH_REDIRECT_URI"]?.trim();
  const productionEmbeddedFallback =
    process.env["NODE_ENV"] === "production" &&
    !client.hasConfiguredCredentials &&
    !overrideRedirectUri &&
    Boolean(envRedirectUri && isExactPublicCallbackUri(envRedirectUri));

  return {
    clientId: client.clientId,
    clientSecret: client.clientSecret,
    redirectUri: productionEmbeddedFallback
      ? DEFAULT_LOCAL_REDIRECT_URI
      : overrideRedirectUri || envRedirectUri || DEFAULT_LOCAL_REDIRECT_URI,
    isCustomClient: client.isCustomClient,
  };
}

export function validateGoogleOAuthConfig(overrides?: Partial<GoogleOAuthConfig>): GoogleOAuthConfig {
  const explicitRedirectUri = overrides?.redirectUri?.trim() || process.env["GOOGLE_OAUTH_REDIRECT_URI"]?.trim();
  const isProduction = process.env["NODE_ENV"] === "production";
  const config = getGoogleOAuthConfig(overrides);

  if (isProduction && config.isCustomClient && !explicitRedirectUri) {
    throw new Error(
      "Invalid Google OAuth redirect URI: GOOGLE_OAUTH_REDIRECT_URI must be explicitly configured as the public HTTPS callback in production.",
    );
  }

  let redirectUrl: URL;
  try {
    redirectUrl = new URL(config.redirectUri);
  } catch {
    throw new Error(`Invalid Google OAuth redirect URI: "${config.redirectUri}"`);
  }

  const isLoopback = isLoopbackRedirectUri(config.redirectUri);
  if (isLoopback) {
    if (isProduction && config.redirectUri !== DEFAULT_LOCAL_REDIRECT_URI) {
      throw new Error(
        `Invalid Google OAuth redirect URI: hosted loopback redirects must use the exact callback ${DEFAULT_LOCAL_REDIRECT_URI}.`,
      );
    }
    if (isProduction && config.isCustomClient) {
      throw new Error(
        "Invalid Google OAuth redirect URI: production requires an explicit public HTTPS callback.",
      );
    }
    return config;
  }

  const invalidPublicRedirect =
    "Invalid Google OAuth redirect URI: public redirects must use HTTPS at /api/oauth/google/callback without query strings, fragments, or user information.";
  if (redirectUrl.protocol !== "https:") {
    throw new Error(invalidPublicRedirect);
  }

  const authorityAndPath = config.redirectUri.slice(config.redirectUri.indexOf("://") + 3);
  const authorityEnd = authorityAndPath.search(/[/?#]/);
  const authority = authorityEnd === -1 ? authorityAndPath : authorityAndPath.slice(0, authorityEnd);
  const pathAndSuffix = authorityEnd === -1 ? "/" : authorityAndPath.slice(authorityEnd);
  const rawPathname = pathAndSuffix.split(/[?#]/, 1)[0] || "/";
  const hasUserInfo = authority.includes("@") || Boolean(redirectUrl.username || redirectUrl.password);

  if (
    redirectUrl.pathname !== PUBLIC_CALLBACK_PATH ||
    rawPathname !== PUBLIC_CALLBACK_PATH ||
    config.redirectUri.includes("?") ||
    config.redirectUri.includes("#") ||
    redirectUrl.search ||
    redirectUrl.hash ||
    hasUserInfo
  ) {
    throw new Error(invalidPublicRedirect);
  }

  if (!config.isCustomClient) {
    throw new Error(
      "Public Google OAuth redirect URI requires custom GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET. " +
      "The default embedded client cannot whitelist operator public domains; use the loopback manual-paste flow or configure an operator-owned Web client.",
    );
  }

  return config;
}

export interface GoogleAuthInitiateResult {
  authUrl: string;
  verifier: string;
  state: string;
}

export function getGoogleRedirectUri(overrides?: Partial<GoogleOAuthConfig>): string {
  return getGoogleOAuthConfig(overrides).redirectUri;
}

export interface GoogleTokenResult {
  accessToken: string;
  refreshToken?: string;
  email?: string;
}

export function initiateGoogleAuth(overrides?: Partial<GoogleOAuthConfig>): GoogleAuthInitiateResult {
  const config = validateGoogleOAuthConfig(overrides);
  const pkce = generatePKCE();
  const state = randomUUID();

  const params = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: config.redirectUri,
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

export async function exchangeGoogleCode(
  code: string,
  verifier: string,
  overrides?: Partial<GoogleOAuthConfig>,
  signal?: AbortSignal,
): Promise<GoogleTokenResult> {
  const config = validateGoogleOAuthConfig(overrides);
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: config.redirectUri,
    }).toString(),
    signal,
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
      signal,
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


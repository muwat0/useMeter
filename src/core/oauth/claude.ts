import { generatePKCE } from "./pkce";

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const REDIRECT_URI = "http://localhost:54545/callback";
const AUTH_URL = "https://claude.ai/oauth/authorize";
const TOKEN_URL = "https://api.anthropic.com/v1/oauth/token";
const SCOPES = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

export interface ClaudeAuthInitiateResult {
  authUrl: string;
  verifier: string;
  state: string;
}

export interface ClaudeTokenResult {
  accessToken: string;
  refreshToken?: string;
  accountEmail?: string;
}

export function initiateClaudeAuth(): ClaudeAuthInitiateResult {
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
  });

  return {
    authUrl: `${AUTH_URL}?${params.toString()}`,
    verifier: pkce.verifier,
    state,
  };
}

export async function exchangeClaudeCode(code: string, verifier: string): Promise<ClaudeTokenResult> {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI,
    }),
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

export async function listenForClaudeCallback(
  expectedState: string,
  timeoutMs: number = 120_000,
): Promise<string> {
  const { promise, resolve, reject } = Promise.withResolvers<string>();

  const server = Bun.serve({
    port: 54545,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/callback") {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");

        if (state !== expectedState) {
          return new Response("Geçersiz state parametresi.", { status: 400 });
        }

        if (!code) {
          return new Response("Yetkilendirme kodu bulunamadı.", { status: 400 });
        }

        resolve(code);
        setTimeout(() => server.stop(), 500);

        return new Response(
          "<html><body style='font-family:sans-serif;background:#0a0a0b;color:#10b981;text-align:center;padding:50px;'><h2>Claude Girişi Başarılı!</h2><p style='color:#a1a1aa;'>Bu sekmeyi kapatıp AI Usage Tracker paneline dönebilirsiniz.</p></body></html>",
          { headers: { "Content-Type": "text/html; charset=utf-8" } },
        );
      }
      return new Response("Not found", { status: 404 });
    },
  });

  const timer = setTimeout(() => {
    server.stop();
    reject(new Error("Zaman aşımı: Claude giriş isteği zamanında tamamlanmadı."));
  }, timeoutMs);

  return promise.finally(() => clearTimeout(timer));
}

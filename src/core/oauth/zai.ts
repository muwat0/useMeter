import { listenForOAuthCallback } from "./callback-server";

const CLIENT_ID = process.env["ZAI_OAUTH_CLIENT_ID"] ?? "client_P8X5CMWmlaRO9gyO-KSqtg";
const AUTHORIZE_URL = process.env["ZAI_OAUTH_AUTHORIZE_URL"] ?? "https://chat.z.ai/api/oauth/authorize";
const TOKEN_URL = process.env["ZAI_OAUTH_TOKEN_URL"] ?? "https://zcode.z.ai/api/v1/oauth/token";
const BIZ_BASE = process.env["ZAI_BIZ_BASE"] ?? "https://api.z.ai";
const BUSINESS_LOGIN_URL = process.env["ZAI_BUSINESS_LOGIN_URL"] ?? "https://api.z.ai/api/auth/z/login";
const KEY_NAME = "oh-my-pi";
const CALLBACK_PORT = 9999;
const CALLBACK_PATH = "/callback";
const REDIRECT_URI = `http://127.0.0.1:${CALLBACK_PORT}${CALLBACK_PATH}`;

export interface ZaiAuthInitiateResult {
  authUrl: string;
  state: string;
  sessionId: string;
}

export function initiateZaiAuth(): ZaiAuthInitiateResult {
  const state = Math.random().toString(36).substring(2);
  const params = new URLSearchParams({
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    client_id: CLIENT_ID,
    state,
  });

  return {
    authUrl: `${AUTHORIZE_URL}?${params.toString()}`,
    state,
    sessionId: state,
  };
}

export async function listenForZaiCallback(expectedState: string, timeoutMs: number = 120_000): Promise<string> {
  return listenForOAuthCallback({
    port: CALLBACK_PORT,
    pathname: CALLBACK_PATH,
    expectedState,
    providerName: "Zhipu AI (GLM)",
    timeoutMs,
  });
}

function unwrapEnvelope(body: any, op: string): any {
  if (body && typeof body === "object" && ("code" in body || "success" in body)) {
    const code = body.code;
    const ok = body.success !== false && (code == null || code === 0 || code === 200 || code === "0" || code === "200");
    if (!ok) {
      throw new Error(`Z.ai ${op} failed: ${body.msg || JSON.stringify(body)}`);
    }
    return body.data !== undefined ? body.data : body;
  }
  return body;
}

export async function exchangeZaiCode(code: string, state: string): Promise<{ apiKey: string; email?: string; accountId?: string }> {
  const tokenRes = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "zai", code, redirect_uri: REDIRECT_URI, state }),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text().catch(() => "");
    throw new Error(`Z.ai token exchange failed: HTTP ${tokenRes.status} ${err}`);
  }

  const tokenJson = await tokenRes.json();
  const tokenData = unwrapEnvelope(tokenJson, "token exchange");
  const oauthAccessToken = tokenData?.zai?.access_token || tokenData?.access_token;
  const email = tokenData?.user?.email;
  const accountId = tokenData?.user?.id ? String(tokenData.user.id) : undefined;

  if (!oauthAccessToken) {
    throw new Error("Z.ai token response missing access token");
  }

  // Business login
  const bizRes = await fetch(BUSINESS_LOGIN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: oauthAccessToken }),
  });
  if (!bizRes.ok) {
    throw new Error(`Z.ai business login failed: HTTP ${bizRes.status}`);
  }
  const bizJson = await bizRes.json();
  const bizData = unwrapEnvelope(bizJson, "business login");
  const bizToken = bizData?.access_token || bizData?.accessToken;
  if (!bizToken) {
    throw new Error("Z.ai business login returned no access token");
  }

  const authHeader = { Authorization: `Bearer ${bizToken}` };

  // Get customer info
  const custRes = await fetch(`${BIZ_BASE}/api/biz/customer/getCustomerInfo`, { headers: authHeader });
  const custJson = await custRes.json();
  const custData = unwrapEnvelope(custJson, "customer lookup");
  const orgs = custData?.organizations || [];
  const org = orgs.find((o: any) => o?.isDefault) || orgs[0];
  const projects = org?.projects || [];
  const project = projects.find((p: any) => p?.isDefault) || projects[0];

  const organizationId = org?.organizationId;
  const projectId = project?.projectId;

  if (!organizationId || !projectId) {
    throw new Error("Z.ai key provisioning failed: no organization/project on account");
  }

  // List keys
  const keysUrl = `${BIZ_BASE}/api/biz/v1/organization/${organizationId}/projects/${projectId}/api_keys`;
  const listRes = await fetch(keysUrl, { headers: authHeader });
  const listJson = await listRes.json();
  const listData = unwrapEnvelope(listJson, "api key list");
  const list = Array.isArray(listData) ? listData : (listData?.list || listData?.keys || listData?.records || []);
  let foundKey = list.find((k: any) => k?.name === KEY_NAME);

  let apiKey = foundKey?.apiKey;
  if (!apiKey) {
    const createRes = await fetch(keysUrl, {
      method: "POST",
      headers: { ...authHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ name: KEY_NAME }),
    });
    const createJson = await createRes.json();
    const createData = unwrapEnvelope(createJson, "api key create");
    apiKey = createData?.apiKey;
  }

  if (!apiKey) {
    throw new Error("Z.ai key provisioning failed: could not obtain api key");
  }

  // Copy secret key
  const copyRes = await fetch(`${keysUrl}/copy/${encodeURIComponent(apiKey)}`, { headers: authHeader });
  const copyJson = await copyRes.json();
  const copyData = unwrapEnvelope(copyJson, "api key copy");
  const secretKey = copyData?.secretKey;

  if (!secretKey) {
    throw new Error("Z.ai key provisioning failed: could not obtain secret key");
  }

  return {
    apiKey: `${apiKey}.${secretKey}`,
    email,
    accountId,
  };
}

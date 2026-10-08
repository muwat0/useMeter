import { afterEach, describe, expect, it } from "bun:test";
import { PollerEngine } from "../src/core/poller/poller";
import type { FetchContext, ProviderAdapter } from "../src/core/providers/adapter";
import { ProviderRegistry } from "../src/core/providers/registry";
import { StorageVault } from "../src/core/storage/vault";
import { createServer, type AppInstance } from "../src/server/app";
import type { StoredCredential, UsageReport } from "../src/types";

const CODEX_DEVICE_AUTH_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const CODEX_DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token";
const CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token";
const XAI_DEVICE_CODE_URL = "https://auth.x.ai/oauth2/device/code";
const XAI_TOKEN_URL = "https://auth.x.ai/oauth2/token";
const XAI_USERINFO_URL = "https://auth.x.ai/oauth2/userinfo";
const INVALID_AUTH_MESSAGE = "Provider rejected synthetic invalid candidate";

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (let index = cleanups.length - 1; index >= 0; index -= 1) cleanups[index]?.();
  cleanups.length = 0;
});

interface ProviderCase {
  name: string;
  provider: "openai-codex" | "xai-oauth";
  initiatePath: string;
  pollPath: string;
}

const providerCases: ProviderCase[] = [
  { name: "Codex", provider: "openai-codex", initiatePath: "/api/oauth/codex/initiate", pollPath: "/api/oauth/codex/poll" },
  { name: "Grok", provider: "xai-oauth", initiatePath: "/api/oauth/xai/initiate", pollPath: "/api/oauth/xai/poll" },
];

interface OAuthMock {
  accessToken: string;
  refreshToken: string;
}

function installOAuthMock(provider: ProviderCase): OAuthMock {
  const originalFetch = globalThis.fetch;
  const mock: OAuthMock = { accessToken: "synthetic-initial-access", refreshToken: "synthetic-initial-refresh" };
  cleanups.push(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : undefined;
    const url = request?.url ?? String(input);
    const method = (init?.method ?? request?.method ?? "GET").toUpperCase();
    const body = typeof init?.body === "string" ? init.body : "";

    if (provider.provider === "openai-codex") {
      if (url === CODEX_DEVICE_AUTH_URL && method === "POST") {
        return Response.json({ device_auth_id: "synthetic-codex-device", user_code: "CODEX-TEST" });
      }
      if (url === CODEX_DEVICE_TOKEN_URL && method === "POST") {
        const requestBody = JSON.parse(body) as { device_auth_id: string; user_code: string };
        if (requestBody.device_auth_id !== "synthetic-codex-device" || requestBody.user_code !== "CODEX-TEST") {
          throw new Error("Codex poll used unexpected device credentials");
        }
        return Response.json({ authorization_code: "synthetic-codex-authorization", code_verifier: "synthetic-codex-verifier" });
      }
      if (url === CODEX_TOKEN_URL && method === "POST") {
        return Response.json({ access_token: mock.accessToken, refresh_token: mock.refreshToken });
      }
    } else {
      if (url === XAI_DEVICE_CODE_URL && method === "POST") {
        return Response.json({ device_code: "synthetic-xai-device", user_code: "XAI-TEST" });
      }
      if (url === XAI_TOKEN_URL && method === "POST") {
        const params = new URLSearchParams(body);
        if (params.get("device_code") !== "synthetic-xai-device") throw new Error("xAI poll used unexpected device code");
        return Response.json({ access_token: mock.accessToken, refresh_token: mock.refreshToken });
      }
      if (url === XAI_USERINFO_URL) {
        return Response.json({ email: "reauth@example.test" });
      }
    }

    throw new Error(`Unexpected ${provider.name} OAuth request: ${method} ${url}`);
  }) as typeof fetch;
  return mock;
}

function createHarness(provider: ProviderCase) {
  const vault = new StorageVault(":memory:");
  vault.setRegistrationAllowed(true);
  cleanups.push(() => vault.close());
  const registry = new ProviderRegistry();
  let usageFetches = 0;
  const adapter: ProviderAdapter = {
    id: provider.provider,
    supports: (id: string) => id.toLowerCase() === provider.provider,
    fetchUsage: async (credential: StoredCredential, _ctx?: FetchContext): Promise<UsageReport> => {
      usageFetches += 1;
      if (credential.secret.includes("invalid")) throw new Error(INVALID_AUTH_MESSAGE);
      return {
        ownerId: credential.ownerId,
        provider: provider.provider,
        credentialId: credential.id,
        accountLabel: credential.accountLabel,
        fetchedAt: Date.now(),
        limits: [],
        health: "healthy",
        source: "live",
      };
    },
  };
  registry.register(adapter);
  const poller = new PollerEngine(vault, registry);
  const app = createServer(vault, poller, registry);
  const oauth = installOAuthMock(provider);
  return { app, vault, oauth, getUsageFetches: () => usageFetches };
}

async function registerUser(app: AppInstance, email: string) {
  const response = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "Password12345678!" }),
  });
  expect(response.status).toBe(201);
  const result = await response.json() as { user: { id: string } };
  const cookie = response.headers.get("Set-Cookie");
  if (!cookie) throw new Error("Registration did not issue an authenticated session cookie");
  return { userId: result.user.id, cookie: cookie.split(";")[0]! };
}

function requestJson(cookie: string, body?: unknown): RequestInit {
  return {
    method: "POST",
    headers: { Cookie: cookie, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

async function authorize(app: AppInstance, provider: ProviderCase, cookie: string, label: string) {
  const initiateResponse = await app.request(provider.initiatePath, requestJson(cookie));
  expect(initiateResponse.status).toBe(200);
  const initiate = await initiateResponse.json() as { data: Record<string, unknown> };
  const pollBody = provider.provider === "openai-codex"
    ? { deviceAuthId: "synthetic-codex-device", userCode: "CODEX-TEST", label }
    : { deviceCode: "synthetic-xai-device", label };
  const response = await app.request(provider.pollPath, requestJson(cookie, pollBody));
  return { response, initiate: initiate.data };
}

describe("Codex and Grok OAuth candidate validation", () => {
  for (const provider of providerCases) {
    it(`${provider.name} failed initial authorization saves no credential or snapshot`, async () => {
      const { app, vault, oauth, getUsageFetches } = createHarness(provider);
      const owner = await registerUser(app, `${provider.provider}-initial-failure@example.test`);
      oauth.accessToken = "synthetic-invalid-initial-access";
      const { response } = await authorize(app, provider, owner.cookie, "Provider Account");

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ status: "error", error: INVALID_AUTH_MESSAGE });
      expect(vault.listCredentials(owner.userId, provider.provider)).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.userId, provider.provider, 24)).toHaveLength(0);
      expect(getUsageFetches()).toBe(1);
    });

    it(`${provider.name} preserves failed reauthorization and successfully replaces the same credential once validated`, async () => {
      const { app, vault, oauth, getUsageFetches } = createHarness(provider);
      const otherTenant = await registerUser(app, `${provider.provider}-other-tenant@example.test`);
      const owner = await registerUser(app, `${provider.provider}-reauth@example.test`);

      oauth.accessToken = "synthetic-valid-initial-access";
      oauth.refreshToken = "synthetic-valid-initial-refresh";
      const initial = await authorize(app, provider, owner.cookie, "Provider Account");
      expect(initial.response.status).toBe(200);
      const initialResult = await initial.response.json() as { status: string; data: { id: string; accountLabel: string } };
      expect(initialResult).toEqual({ status: "complete", data: { id: expect.any(String), accountLabel: "Provider Account" } });
      const credentialId = initialResult.data.id;
      expect(vault.updateCredential(owner.userId, credentialId, { accent: "emerald" })).toBe(true);
      vault.saveUsageSnapshot(owner.userId, {
        provider: provider.provider,
        credentialId,
        accountLabel: "Provider Account",
        fetchedAt: Date.now() - 60_000,
        limits: [],
        health: "healthy",
        source: "live",
      });
      const baselineCredential = vault.getCredential(owner.userId, credentialId);
      const baselineSnapshots = vault.getSnapshotHistory(owner.userId, provider.provider, 24);
      expect(baselineSnapshots).toHaveLength(2);
      expect(getUsageFetches()).toBe(1);

      oauth.accessToken = "synthetic-invalid-reauth-access";
      oauth.refreshToken = "synthetic-invalid-reauth-refresh";
      const failed = await authorize(app, provider, owner.cookie, "Provider Account");
      expect(failed.response.status).toBe(200);
      expect(await failed.response.json()).toEqual({ status: "error", error: INVALID_AUTH_MESSAGE });
      expect(vault.listCredentials(owner.userId, provider.provider)).toHaveLength(1);
      expect(vault.getCredential(owner.userId, credentialId)).toEqual(baselineCredential);
      expect(vault.getSnapshotHistory(owner.userId, provider.provider, 24)).toEqual(baselineSnapshots);
      expect(getUsageFetches()).toBe(2);

      oauth.accessToken = "synthetic-valid-replacement-access";
      oauth.refreshToken = "synthetic-valid-replacement-refresh";
      const successful = await authorize(app, provider, owner.cookie, "Provider Account");
      expect(successful.response.status).toBe(200);
      expect(await successful.response.json()).toEqual({
        status: "complete",
        data: { id: credentialId, accountLabel: "Provider Account" },
      });
      expect(vault.listCredentials(owner.userId, provider.provider)).toHaveLength(1);
      expect(vault.getCredential(owner.userId, credentialId)).toMatchObject({
        id: credentialId,
        ownerId: owner.userId,
        provider: provider.provider,
        accountLabel: "Provider Account",
        credentialType: "oauth",
        secret: "synthetic-valid-replacement-access",
        metadata: { refreshToken: "synthetic-valid-replacement-refresh" },
        accent: "emerald",
      });
      expect(vault.getCredential(otherTenant.userId, credentialId)).toBeNull();
      expect(vault.listCredentials(otherTenant.userId, provider.provider)).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.userId, provider.provider, 24)).toHaveLength(baselineSnapshots.length + 1);
      expect(getUsageFetches()).toBe(3);
    });
  }
});

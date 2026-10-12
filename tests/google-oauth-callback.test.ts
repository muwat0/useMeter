import { describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StorageVault } from "../src/core/storage/vault";
import { PollerEngine } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import { GoogleAntigravityAdapter } from "../src/core/providers/google-antigravity";
import { getGoogleOAuthConfig, type GoogleOAuthConfig, type GoogleTokenResult } from "../src/core/oauth/google";
import type { UsageReport } from "../src/types";
import { AuthService } from "../src/core/auth/auth";
import { createServer, type AppInstance, type ServerOptions } from "../src/server/app";

const GOOGLE_ENV_KEYS = [
  "NODE_ENV",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GOOGLE_OAUTH_REDIRECT_URI",
  "CREDENTIAL_METADATA_ENCRYPTION",
  "USAGE_MASTER_KEY",
] as const;
const GOOGLE_LOOPBACK_CALLBACK = "http://127.0.0.1:51121/oauth-callback";
const LEGACY_PUBLIC_CALLBACK = "https://usemeter.example.com/api/oauth/google/callback";

type GoogleEnvSnapshot = Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>>;

function snapshotGoogleEnv(): GoogleEnvSnapshot {
  const snapshot: GoogleEnvSnapshot = {};
  for (const key of GOOGLE_ENV_KEYS) snapshot[key] = process.env[key];
  return snapshot;
}

function restoreGoogleEnv(snapshot: GoogleEnvSnapshot) {
  for (const key of GOOGLE_ENV_KEYS) {
    const value = snapshot[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function useHostedEmbeddedGoogleClient() {
  process.env["NODE_ENV"] = "production";
  process.env["GOOGLE_OAUTH_CLIENT_ID"] = "";
  process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "";
  process.env["GOOGLE_OAUTH_REDIRECT_URI"] = LEGACY_PUBLIC_CALLBACK;
  process.env["USAGE_MASTER_KEY"] = "synthetic-google-test-master-key";
}

const successfulValidationAdapter: ProviderAdapter = {
  id: "antigravity",
  supports: provider => provider === "antigravity",
  async fetchUsage(credential: Parameters<ProviderAdapter["fetchUsage"]>[0]): Promise<UsageReport> {
    return {
      ownerId: credential.ownerId,
      provider: credential.provider,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits: [],
      health: "healthy",
      stale: false,
      source: "live",
    };
  },
};

const failedValidationAdapter: ProviderAdapter = {
  id: "antigravity",
  supports: provider => provider === "antigravity",
  async fetchUsage(credential: Parameters<ProviderAdapter["fetchUsage"]>[0]): Promise<UsageReport> {
    return {
      ownerId: credential.ownerId,
      provider: credential.provider,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits: [],
      error: "synthetic provider validation failure",
    };
  },
};

function context(
  adapter: ProviderAdapter = successfulValidationAdapter,
  options?: ServerOptions,
  dbPath = ":memory:",
) {
  const vault = new StorageVault(dbPath);
  const registry = new ProviderRegistry();
  registry.register(adapter);
  const poller = new PollerEngine(vault, registry);
  const auth = new AuthService(vault);
  const app = createServer(vault, poller, registry, auth, options);
  return { vault, app, auth };
}

async function register(
  auth: AuthService,
  email: string,
): Promise<{ id: string; cookie: string }> {
  const result = await auth.register(email, "Password12345678!");
  if (!result.success) throw new Error("Synthetic test user registration failed");
  return {
    id: result.data.user.id,
    cookie: `usage_session=${encodeURIComponent(result.data.token)}`,
  };
}

async function initiate(app: AppInstance, cookie: string) {
  const response = await app.request("/api/oauth/google/initiate", {
    method: "POST",
    headers: { Cookie: cookie },
  });
  const body = await response.json() as {
    success: boolean;
    data?: {
      authUrl: string;
      sessionId: string;
      redirectUri: string;
      manualCallback: boolean;
      expiresIn: number;
    };
  };
  if (!response.ok || !body.data) throw new Error("Synthetic Google OAuth initiation failed");
  return body.data;
}

function callbackUrl(state: string, code = "synthetic-code") {
  const params = new URLSearchParams({ code, state });
  return `${GOOGLE_LOOPBACK_CALLBACK}?${params.toString()}`;
}

async function postManualCallback(
  app: AppInstance,
  cookie: string,
  sessionId: string,
  callbackInput: string,
) {
  return app.request("/api/oauth/google/manual", {
    method: "POST",
    headers: { Cookie: cookie, "Content-Type": "application/json" },
    body: JSON.stringify({ sessionId, callbackInput }),
  });
}

async function status(app: AppInstance, cookie: string, sessionId: string) {
  return app.request(`/api/oauth/status/${encodeURIComponent(sessionId)}`, {
    headers: { Cookie: cookie },
  });
}

describe("Google OAuth callback handling", () => {
  it("rejects unknown state and ambiguous public callback parameters without exposing input", async () => {
    const { vault, app } = context();
    try {
      const unknownState = await app.request("/api/oauth/google/callback?state=unknown&code=synthetic-code");
      expect(unknownState.status).toBe(400);
      expect(await unknownState.text()).toContain("Invalid or expired authorization session");

      const duplicateState = await app.request(
        "/api/oauth/google/callback?state=first&state=second&code=synthetic-code",
      );
      expect(duplicateState.status).toBe(400);
      const duplicateBody = await duplicateState.text();
      expect(duplicateBody).toContain("Invalid authorization response");
      expect(duplicateBody).not.toContain("synthetic-code");
    } finally {
      vault.close();
    }
  });

  it("initiates hosted embedded-client OAuth with the loopback manual-paste mode despite an old public URI", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    const { vault, app, auth } = context();
    try {
      const user = await register(auth, "google-manual-initiate@example.com");
      const data = await initiate(app, user.cookie);
      expect(data.redirectUri).toBe(GOOGLE_LOOPBACK_CALLBACK);
      expect(data.manualCallback).toBe(true);
      expect(data.expiresIn).toBe(600);
      expect(new URL(data.authUrl).searchParams.get("redirect_uri")).toBe(GOOGLE_LOOPBACK_CALLBACK);
      expect(new URL(data.authUrl).searchParams.get("state")).toBe(data.sessionId);
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("supports the configured Web-client callback and exchanges with the initiation-time config", async () => {
    const env = snapshotGoogleEnv();
    process.env["NODE_ENV"] = "production";
    process.env["USAGE_MASTER_KEY"] = "synthetic-google-test-master-key";
    process.env["CREDENTIAL_METADATA_ENCRYPTION"] = "enabled";
    process.env["GOOGLE_OAUTH_CLIENT_ID"] = "first-web-client.apps.googleusercontent.com";
    process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "first-web-client-secret";
    process.env["GOOGLE_OAUTH_REDIRECT_URI"] = LEGACY_PUBLIC_CALLBACK;
    let captured: { code: string; verifier: string; config?: Partial<GoogleOAuthConfig> } | undefined;
    const options: ServerOptions = {
      googleOAuthExchange: async (code, verifier, config) => {
        captured = { code, verifier, config };
        return {
          accessToken: "synthetic-web-access-token",
          refreshToken: "synthetic-web-refresh-token",
          email: "web-client@example.com",
        };
      },
    };
    const { vault, app, auth } = context(successfulValidationAdapter, options);
    try {
      const user = await register(auth, "google-web-callback@example.com");
      const data = await initiate(app, user.cookie);
      expect(data.redirectUri).toBe(LEGACY_PUBLIC_CALLBACK);
      expect(data.manualCallback).toBe(false);

      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "rotated-web-client.apps.googleusercontent.com";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "rotated-web-client-secret";
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://new.example.com/api/oauth/google/callback";
      const params = new URLSearchParams({ code: "synthetic-web-code", state: data.sessionId });
      const callback = await app.request(`/api/oauth/google/callback?${params.toString()}`);
      expect(callback.status).toBe(200);
      expect(await callback.text()).toContain("Google Login Successful");
      expect(captured).toMatchObject({
        code: "synthetic-web-code",
        config: {
          clientId: "first-web-client.apps.googleusercontent.com",
          clientSecret: "first-web-client-secret",
          redirectUri: LEGACY_PUBLIC_CALLBACK,
        },
      });

      const credentials = vault.listCredentials(user.id);
      expect(credentials).toHaveLength(1);
      expect(credentials[0]?.metadata).toMatchObject({
        refreshToken: "synthetic-web-refresh-token",
        googleOAuthClientId: "first-web-client.apps.googleusercontent.com",
        googleOAuthClientSecret: "first-web-client-secret",
      });
      const replay = await app.request(`/api/oauth/google/callback?${params.toString()}`);
      expect(replay.status).toBe(400);
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("binds manual callbacks to the owner and rejects non-exact, incomplete, mismatched, or duplicate callback URLs", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    let exchangeCalls = 0;
    const { vault, app, auth } = context(successfulValidationAdapter, {
      googleOAuthExchange: async () => {
        exchangeCalls++;
        return { accessToken: "synthetic-access", email: "never-used@example.com" };
      },
    });
    try {
      const alice = await register(auth, "google-manual-owner@example.com");
      const bob = await register(auth, "google-manual-other@example.com");
      const data = await initiate(app, alice.cookie);

      const otherOwner = await postManualCallback(app, bob.cookie, data.sessionId, callbackUrl(data.sessionId));
      expect(otherOwner.status).toBe(404);
      const invalidInputs = [
        "code=synthetic-code&state=" + encodeURIComponent(data.sessionId),
        `http://localhost:51121/oauth-callback?code=synthetic-code&state=${encodeURIComponent(data.sessionId)}`,
        `http://127.0.0.1:51121/wrong-path?code=synthetic-code&state=${encodeURIComponent(data.sessionId)}`,
        `${GOOGLE_LOOPBACK_CALLBACK}?state=${encodeURIComponent(data.sessionId)}`,
        `${GOOGLE_LOOPBACK_CALLBACK}?code=synthetic-code`,
        `${GOOGLE_LOOPBACK_CALLBACK}?code=synthetic-code&state=wrong-state`,
        `${GOOGLE_LOOPBACK_CALLBACK}?code=first&code=second&state=${encodeURIComponent(data.sessionId)}`,
        `${GOOGLE_LOOPBACK_CALLBACK}?code=synthetic-code&state=${encodeURIComponent(data.sessionId)}&state=duplicate`,
      ];
      for (const callbackInput of invalidInputs) {
        const rejected = await postManualCallback(app, alice.cookie, data.sessionId, callbackInput);
        expect(rejected.status).toBe(400);
        expect(await rejected.text()).not.toContain("synthetic-code");
      }

      const pending = await status(app, alice.cookie, data.sessionId);
      expect((await pending.json() as { status: string }).status).toBe("pending");
      expect(exchangeCalls).toBe(0);

      const denied = await postManualCallback(
        app,
        alice.cookie,
        data.sessionId,
        `${GOOGLE_LOOPBACK_CALLBACK}?error=access_denied&state=${encodeURIComponent(data.sessionId)}`,
      );
      expect(denied.status).toBe(400);
      expect(await denied.text()).not.toContain("access_denied");
      expect((await (await status(app, alice.cookie, data.sessionId)).json() as { status: string }).status)
        .toBe("error");
      expect(exchangeCalls).toBe(0);
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("expires manual sessions at ten minutes before exchanging a submitted callback", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    let now = 1_800_000_000_000;
    let exchangeCalls = 0;
    const { vault, app, auth } = context(successfulValidationAdapter, {
      oauthNow: () => now,
      googleOAuthExchange: async () => {
        exchangeCalls++;
        return { accessToken: "synthetic-access" };
      },
    });
    try {
      const user = await register(auth, "google-manual-expired@example.com");
      const data = await initiate(app, user.cookie);
      now += 10 * 60 * 1000;

      const expired = await postManualCallback(app, user.cookie, data.sessionId, callbackUrl(data.sessionId));
      expect(expired.status).toBe(400);
      expect(await expired.text()).toContain("Authorization session expired");
      expect((await (await status(app, user.cookie, data.sessionId)).json() as { status: string }).status)
        .toBe("error");
      expect(exchangeCalls).toBe(0);
      now += 60 * 1000;
      expect((await status(app, user.cookie, data.sessionId)).status).toBe(404);
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("checks the OAuth deadline at the credential commit boundary without an interim request", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    let now = 1_800_000_000_000;
    const validation = Promise.withResolvers<UsageReport>();
    const validationStarted = Promise.withResolvers<void>();
    const delayedAdapter: ProviderAdapter = {
      id: "antigravity",
      supports: provider => provider === "antigravity",
      async fetchUsage(): Promise<UsageReport> {
        validationStarted.resolve();
        return validation.promise;
      },
    };
    const { vault, app, auth } = context(delayedAdapter, {
      oauthNow: () => now,
      googleOAuthExchange: async () => ({
        accessToken: "synthetic-late-google-candidate",
        email: "late-google@example.test",
      }),
    });
    let cookie = "";
    let sessionId = "";
    let callback: Promise<Response> | undefined;
    let validationResolved = false;
    const report = (ownerId: string): UsageReport => ({
      ownerId,
      provider: "antigravity",
      accountLabel: "late-google@example.test",
      fetchedAt: now,
      limits: [],
      health: "healthy",
      stale: false,
      source: "live",
    });
    try {
      const user = await register(auth, "google-late-commit@example.com");
      cookie = user.cookie;
      const data = await initiate(app, cookie);
      sessionId = data.sessionId;
      callback = postManualCallback(app, cookie, sessionId, callbackUrl(sessionId));
      await validationStarted.promise;

      now += 10 * 60 * 1000 + 1_000;
      validation.resolve(report(user.id));
      validationResolved = true;

      expect((await callback).status).toBe(404);
      expect(vault.listCredentials(user.id, "antigravity")).toHaveLength(0);
      expect(vault.getSnapshotHistory(user.id, "antigravity", 24)).toHaveLength(0);
    } finally {
      if (!validationResolved) {
        if (cookie && sessionId) {
          await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
            method: "DELETE",
            headers: { Cookie: cookie },
          });
        }
        validation.resolve(report(""));
        await callback?.catch(() => {});
      }
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("consumes an in-flight manual callback before exchange and does not reveal exchange failures", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    let rejectExchange!: (error: Error) => void;
    let startExchange!: () => void;
    let exchangeCalls = 0;
    const exchangeStarted = new Promise<void>(resolve => {
      startExchange = resolve;
    });
    const exchangeResult = new Promise<GoogleTokenResult>((_resolve, reject) => {
      rejectExchange = reject;
    });
    const { vault, app, auth } = context(successfulValidationAdapter, {
      googleOAuthExchange: async () => {
        exchangeCalls++;
        startExchange();
        return exchangeResult;
      },
    });
    try {
      const user = await register(auth, "google-manual-inflight@example.com");
      const data = await initiate(app, user.cookie);
      const callbackInput = callbackUrl(data.sessionId);
      const inFlight = postManualCallback(app, user.cookie, data.sessionId, callbackInput);
      await exchangeStarted;
      const replayDuringExchange = await postManualCallback(app, user.cookie, data.sessionId, callbackInput);
      expect(replayDuringExchange.status).toBe(400);
      expect(await replayDuringExchange.text()).toContain("already used");
      expect(exchangeCalls).toBe(1);

      rejectExchange(new Error("private-provider-error-and-secret"));
      const failed = await inFlight;
      expect(failed.status).toBe(400);
      const errorBody = await failed.text();
      expect(errorBody).toContain("Authorization failed");
      expect(errorBody).not.toContain("private-provider-error-and-secret");
      expect(errorBody).not.toContain("synthetic-code");
      expect((await (await status(app, user.cookie, data.sessionId)).json() as { status: string }).status)
        .toBe("error");
      const replayAfterFailure = await postManualCallback(app, user.cookie, data.sessionId, callbackInput);
      expect(replayAfterFailure.status).toBe(400);
      expect(exchangeCalls).toBe(1);
      expect(vault.listCredentials(user.id)).toHaveLength(0);
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("stores refresh metadata encrypted and refreshes with the initiating OAuth client", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    process.env["CREDENTIAL_METADATA_ENCRYPTION"] = "enabled";
    const dbPath = join(tmpdir(), `test-google-oauth-${randomUUID()}.db`);
    const initiatingConfig = getGoogleOAuthConfig();
    let resolveExchange!: (tokens: GoogleTokenResult) => void;
    let startExchange!: () => void;
    let exchangeCalls = 0;
    let exchangeConfig: Partial<GoogleOAuthConfig> | undefined;
    const exchangeStarted = new Promise<void>(resolve => {
      startExchange = resolve;
    });
    const exchangeResult = new Promise<GoogleTokenResult>(resolve => {
      resolveExchange = resolve;
    });
    const { vault, app, auth } = context(successfulValidationAdapter, {
      googleOAuthExchange: async (_code, _verifier, config) => {
        exchangeCalls++;
        exchangeConfig = config;
        startExchange();
        return exchangeResult;
      },
    }, dbPath);
    let rawDb: Database | undefined;
    try {
      rawDb = new Database(dbPath);
      const user = await register(auth, "google-encrypted-refresh@example.com");
      const data = await initiate(app, user.cookie);
      expect(data.manualCallback).toBe(true);

      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "rotated-environment-client.apps.googleusercontent.com";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "rotated-environment-client-secret";
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = LEGACY_PUBLIC_CALLBACK;

      const callbackInput = callbackUrl(data.sessionId, "synthetic-manual-code");
      const inFlight = postManualCallback(app, user.cookie, data.sessionId, callbackInput);
      await exchangeStarted;
      const replayDuringExchange = await postManualCallback(app, user.cookie, data.sessionId, callbackInput);
      expect(replayDuringExchange.status).toBe(400);
      expect(exchangeCalls).toBe(1);
      resolveExchange({
        accessToken: "synthetic-manual-access-token",
        refreshToken: "synthetic-manual-refresh-token",
        email: "encrypted-google@example.com",
      });
      const completed = await inFlight;
      expect(completed.status).toBe(200);
      expect(exchangeConfig).toEqual({
        clientId: initiatingConfig.clientId,
        clientSecret: initiatingConfig.clientSecret,
        redirectUri: initiatingConfig.redirectUri,
      });
      expect((await (await status(app, user.cookie, data.sessionId)).json() as { status: string }).status)
        .toBe("complete");

      const saved = vault.listCredentials(user.id)[0];
      expect(saved).toBeDefined();
      expect(saved?.metadata).toMatchObject({
        refreshToken: "synthetic-manual-refresh-token",
        googleOAuthClientId: initiatingConfig.clientId,
        googleOAuthClientSecret: initiatingConfig.clientSecret,
      });

      const rawMetadataRow = rawDb.prepare(
        "SELECT metadata FROM credentials WHERE owner_id = ? AND provider = 'antigravity'",
      ).get(user.id) as { metadata: string | null } | undefined;
      expect(rawMetadataRow?.metadata).toBeTruthy();
      const metadataEnvelope = JSON.parse(rawMetadataRow!.metadata!) as Record<string, unknown>;
      expect(metadataEnvelope["$vault"]).toBe(1);
      expect(metadataEnvelope["ciphertext"]).toBeTruthy();
      expect(rawMetadataRow!.metadata).not.toContain("synthetic-manual-refresh-token");
      expect(rawMetadataRow!.metadata).not.toContain(initiatingConfig.clientSecret);

      const dataResponse = await app.request("/api/data", { headers: { Cookie: user.cookie } });
      const publicData = await dataResponse.text();
      expect(publicData).not.toContain("synthetic-manual-refresh-token");
      expect(publicData).not.toContain(initiatingConfig.clientSecret);
      const credentialsResponse = await app.request("/api/credentials", { headers: { Cookie: user.cookie } });
      const publicCredentials = await credentialsResponse.text();
      expect(publicCredentials).not.toContain("synthetic-manual-refresh-token");
      expect(publicCredentials).not.toContain(initiatingConfig.clientSecret);
      const usageResponse = await app.request("/api/usage", { headers: { Cookie: user.cookie } });
      const publicUsage = await usageResponse.text();
      expect(publicUsage).not.toContain("synthetic-manual-refresh-token");
      expect(publicUsage).not.toContain(initiatingConfig.clientSecret);
      const pollResponse = await app.request("/api/poll", {
        method: "POST",
        headers: { Cookie: user.cookie },
      });
      const publicPoll = await pollResponse.text();
      expect(publicPoll).not.toContain("synthetic-manual-refresh-token");
      expect(publicPoll).not.toContain(initiatingConfig.clientSecret);

      const savedCredential = vault.getCredential(user.id, saved!.id)!;
      const refreshBodies: string[] = [];
      const providerAccessHeaders: string[] = [];
      const syntheticProviderFetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url === "https://oauth2.googleapis.com/token") {
          refreshBodies.push(init?.body?.toString() ?? "");
          return new Response(JSON.stringify({ access_token: "synthetic-renewed-access-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url.endsWith("/v1internal:loadCodeAssist")) {
          providerAccessHeaders.push(new Headers(init?.headers).get("Authorization") || "");
          return new Response(JSON.stringify({ cloudaicompanionProject: "synthetic-project" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url.endsWith("/v1internal:retrieveUserQuotaSummary")) {
          providerAccessHeaders.push(new Headers(init?.headers).get("Authorization") || "");
          return new Response(JSON.stringify({
            groups: [{ displayName: "Gemini", buckets: [{ bucketId: "5h", remainingFraction: 0.75 }] }],
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`Unexpected synthetic provider URL: ${url}`);
      }) as unknown as typeof fetch;
      const report = await new GoogleAntigravityAdapter().fetchUsage(savedCredential, {
        fetch: syntheticProviderFetch,
      });
      expect(report.error).toBeUndefined();

      const refreshParams = new URLSearchParams(refreshBodies[0]);
      expect(refreshParams.get("client_id")).toBe(initiatingConfig.clientId);
      expect(refreshParams.get("client_secret")).toBe(initiatingConfig.clientSecret);
      expect(refreshParams.get("refresh_token")).toBe("synthetic-manual-refresh-token");
      expect(refreshParams.get("grant_type")).toBe("refresh_token");
      expect(refreshParams.has("redirect_uri")).toBe(false);
      expect(providerAccessHeaders).toEqual([
        "Bearer synthetic-renewed-access-token",
        "Bearer synthetic-renewed-access-token",
      ]);
    } finally {
      rawDb?.close();
      vault.close();
      rmSync(dbPath, { force: true });
      rmSync(`${dbPath}-wal`, { force: true });
      rmSync(`${dbPath}-shm`, { force: true });
      restoreGoogleEnv(env);
    }
  });

  it("keeps the prior refresh-token client when reauthorization omits a replacement refresh token", async () => {
    const env = snapshotGoogleEnv();
    process.env["NODE_ENV"] = "production";
    process.env["USAGE_MASTER_KEY"] = "synthetic-google-test-master-key";
    process.env["CREDENTIAL_METADATA_ENCRYPTION"] = "enabled";
    process.env["GOOGLE_OAUTH_CLIENT_ID"] = "client-b.apps.googleusercontent.com";
    process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "client-b-secret";
    process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";
    const { vault, app, auth } = context(successfulValidationAdapter, {
      googleOAuthExchange: async () => ({
        accessToken: "reauthorized-access-token",
        email: "reauthorized-google@example.com",
      }),
    });
    try {
      const user = await register(auth, "google-client-rotation@example.com");
      vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "antigravity",
        accountLabel: "reauthorized-google@example.com",
        credentialType: "oauth",
        secret: "previous-access-token",
        metadata: {
          refreshToken: "client-a-refresh-token",
          googleOAuthClientId: "client-a.apps.googleusercontent.com",
          googleOAuthClientSecret: "client-a-secret",
        },
      });

      const data = await initiate(app, user.cookie);
      const params = new URLSearchParams({ code: "client-b-reauthorization-code", state: data.sessionId });
      const callback = await app.request(`/api/oauth/google/callback?${params.toString()}`);
      expect(callback.status).toBe(200);
      expect(await callback.text()).toContain("Google Login Successful");

      const credential = vault.listCredentials(user.id)[0]!;
      expect(credential.secret).toBe("reauthorized-access-token");
      expect(credential.metadata).toMatchObject({
        refreshToken: "client-a-refresh-token",
        googleOAuthClientId: "client-a.apps.googleusercontent.com",
        googleOAuthClientSecret: "client-a-secret",
      });

      let refreshBody = "";
      const syntheticProviderFetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url === "https://oauth2.googleapis.com/token") {
          refreshBody = init?.body?.toString() ?? "";
          return new Response(JSON.stringify({ access_token: "client-a-refreshed-access" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url.endsWith("/v1internal:loadCodeAssist")) {
          return new Response(JSON.stringify({ cloudaicompanionProject: "synthetic-project" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url.endsWith("/v1internal:retrieveUserQuotaSummary")) {
          return new Response(JSON.stringify({
            groups: [{ displayName: "Gemini", buckets: [{ bucketId: "5h", remainingFraction: 0.5 }] }],
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`Unexpected synthetic provider URL: ${url}`);
      }) as unknown as typeof fetch;
      const report = await new GoogleAntigravityAdapter().fetchUsage(
        vault.getCredential(user.id, credential.id)!,
        { fetch: syntheticProviderFetch },
      );
      expect(report.error).toBeUndefined();
      const refreshParams = new URLSearchParams(refreshBody);
      expect(refreshParams.get("client_id")).toBe("client-a.apps.googleusercontent.com");
      expect(refreshParams.get("client_secret")).toBe("client-a-secret");
      expect(refreshParams.get("refresh_token")).toBe("client-a-refresh-token");
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("keeps an existing matching credential when staged candidate validation fails", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    const { vault, app, auth } = context(failedValidationAdapter, {
      googleOAuthExchange: async () => ({
        accessToken: "synthetic-invalid-candidate-token",
        refreshToken: "synthetic-invalid-candidate-refresh",
        email: "preserved-google@example.com",
      }),
    });
    try {
      const user = await register(auth, "google-preserve-old@example.com");
      const previous = vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "antigravity",
        accountLabel: "preserved-google@example.com",
        credentialType: "oauth",
        secret: "previous-valid-access-token",
        metadata: { refreshToken: "previous-valid-refresh-token" },
      });
      const data = await initiate(app, user.cookie);
      const failed = await postManualCallback(app, user.cookie, data.sessionId, callbackUrl(data.sessionId));
      expect(failed.status).toBe(400);
      expect(await failed.text()).not.toContain("synthetic provider validation failure");

      const retained = vault.getCredential(user.id, previous.id);
      expect(retained?.secret).toBe("previous-valid-access-token");
      expect(retained?.metadata?.["refreshToken"]).toBe("previous-valid-refresh-token");
      expect(vault.listCredentials(user.id)).toHaveLength(1);
    } finally {
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("applies per-owner capacity, reports retry guidance, and releases failed and canceled slots", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    const { vault, app, auth } = context(successfulValidationAdapter, { oauthNow: () => 1_800_000_000_000 });
    const sessions: Array<{ sessionId: string }> = [];
    let ownerCookie = "";
    try {
      const owner = await register(auth, "google-capacity-owner@example.com");
      const foreign = await register(auth, "google-capacity-foreign@example.com");
      ownerCookie = owner.cookie;

      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "synthetic-partial-client-id";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "";
      for (let attempt = 0; attempt < 5; attempt++) {
        const failedInitiation = await app.request("/api/oauth/google/initiate", {
          method: "POST",
          headers: { Cookie: owner.cookie },
        });
        expect(failedInitiation.status).toBe(400);
      }
      useHostedEmbeddedGoogleClient();

      for (let index = 0; index < 5; index++) {
        sessions.push(await initiate(app, owner.cookie));
      }
      const rejected = await app.request("/api/oauth/google/initiate", {
        method: "POST",
        headers: { Cookie: owner.cookie },
      });
      expect(rejected.status).toBe(429);
      expect(rejected.headers.get("Retry-After")).toBe("60");
      expect(await rejected.json()).toMatchObject({ errorCode: "OAUTH_CAPACITY" });

      const first = sessions[0]!;
      const foreignCancel = await app.request(`/api/oauth/sessions/${encodeURIComponent(first.sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: foreign.cookie },
      });
      expect(foreignCancel.status).toBe(404);
      expect((await status(app, owner.cookie, first.sessionId)).status).toBe(200);

      const canceled = await app.request(`/api/oauth/sessions/${encodeURIComponent(first.sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: owner.cookie },
      });
      expect(canceled.status).toBe(200);
      expect((await status(app, owner.cookie, first.sessionId)).status).toBe(404);
      sessions.push(await initiate(app, owner.cookie));
      expect(sessions[5]?.sessionId).toBeTruthy();
    } finally {
      if (ownerCookie) {
        for (const session of sessions) {
          await app.request(`/api/oauth/sessions/${encodeURIComponent(session.sessionId)}`, {
            method: "DELETE",
            headers: { Cookie: ownerCookie },
          });
        }
      }
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("claims manual callbacks exclusively and blocks credential commits after cancellation", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    const exchange = Promise.withResolvers<GoogleTokenResult>();
    const exchangeStarted = Promise.withResolvers<void>();
    let exchangeCalls = 0;
    const { vault, app, auth } = context(successfulValidationAdapter, {
      oauthNow: () => 1_800_000_000_000,
      googleOAuthExchange: async () => {
        exchangeCalls++;
        exchangeStarted.resolve();
        return exchange.promise;
      },
    });
    let sessionId = "";
    let ownerCookie = "";
    let callbackPromise: Promise<Response> | undefined;
    let exchangeResolved = false;
    try {
      const owner = await register(auth, "google-cancel-owner@example.com");
      const foreign = await register(auth, "google-cancel-foreign@example.com");
      const data = await initiate(app, owner.cookie);
      sessionId = data.sessionId;
      ownerCookie = owner.cookie;
      callbackPromise = postManualCallback(app, owner.cookie, data.sessionId, callbackUrl(data.sessionId));
      await exchangeStarted.promise;

      const replay = await postManualCallback(app, owner.cookie, data.sessionId, callbackUrl(data.sessionId));
      expect(replay.status).toBe(400);
      expect(exchangeCalls).toBe(1);
      const foreignCancel = await app.request(`/api/oauth/sessions/${encodeURIComponent(data.sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: foreign.cookie },
      });
      expect(foreignCancel.status).toBe(404);
      const canceled = await app.request(`/api/oauth/sessions/${encodeURIComponent(data.sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: owner.cookie },
      });
      expect(canceled.status).toBe(200);

      exchange.resolve({ accessToken: "synthetic-canceled-access", email: "cancelled@example.com" });
      exchangeResolved = true;
      expect((await callbackPromise).status).toBe(404);
      expect(vault.listCredentials(owner.id)).toHaveLength(0);
      expect((await status(app, owner.cookie, data.sessionId)).status).toBe(404);
    } finally {
      if (!exchangeResolved) {
        if (sessionId && ownerCookie) {
          await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
            method: "DELETE",
            headers: { Cookie: ownerCookie },
          });
        }
        exchange.resolve({ accessToken: "synthetic-canceled-access", email: "cancelled@example.com" });
        await callbackPromise?.catch(() => {});
      }
      vault.close();
      restoreGoogleEnv(env);
    }
  });
});

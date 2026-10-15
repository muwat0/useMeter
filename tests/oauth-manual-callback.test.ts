import { createHash } from "node:crypto";
import { describe, expect, it } from "bun:test";
import { AuthService } from "../src/core/auth/auth";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import { ProviderRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { StorageVault } from "../src/core/storage/vault";
import type { GoogleOAuthConfig, GoogleTokenResult } from "../src/core/oauth/google";
import { createServer, type AppInstance, type ServerOptions } from "../src/server/app";
import type { StoredCredential, UsageReport } from "../src/types";

const GOOGLE_ENV_KEYS = [
  "NODE_ENV",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GOOGLE_OAUTH_REDIRECT_URI",
  "CREDENTIAL_METADATA_ENCRYPTION",
  "USAGE_MASTER_KEY",
] as const;
const GOOGLE_LOOPBACK_CALLBACK = "http://127.0.0.1:51121/oauth-callback";
const GOOGLE_PUBLIC_CALLBACK = "https://usemeter.example.com/api/oauth/google/callback";

type ManualInput = "url";
type ManualFlowId = "claude" | "gemini-cli" | "zai";

interface ManualFlow {
  id: ManualFlowId;
  endpoint: string;
  provider: string;
  manualInput: ManualInput;
  redirectUri?: string;
}

interface OAuthInitiationData {
  authUrl: string;
  sessionId: string;
  expiresIn: number;
  manualCallback: boolean;
  manualInput?: ManualInput;
  redirectUri?: string;
}

const MANUAL_FLOWS: readonly ManualFlow[] = [
  {
    id: "claude",
    endpoint: "/api/oauth/claude/initiate",
    provider: "anthropic",
    manualInput: "url",
    redirectUri: "http://localhost:54545/callback",
  },
  {
    id: "gemini-cli",
    endpoint: "/api/oauth/gemini-cli/initiate",
    provider: "google-gemini-cli",
    manualInput: "url",
    redirectUri: "http://127.0.0.1:8085/oauth2callback",
  },
  {
    id: "zai",
    endpoint: "/api/oauth/zai/initiate",
    provider: "zai",
    manualInput: "url",
    redirectUri: "http://127.0.0.1:9999/callback",
  },
];

const VALIDATION_PROVIDERS = [
  "anthropic",
  "google-gemini-cli",
  "zai",
  "antigravity",
] as const;

type ValidationHook = (credential: StoredCredential) => void | Promise<void>;

function makeValidationAdapter(provider: string, onValidate?: ValidationHook): ProviderAdapter {
  const adapter: ProviderAdapter = {
    id: `synthetic-${provider}`,
    supports: candidate => candidate === provider,
    async fetchUsage(credential: StoredCredential): Promise<UsageReport> {
      await onValidate?.(credential);
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
  return adapter;
}

function context(options: ServerOptions = {}, onValidate?: ValidationHook) {
  const vault = new StorageVault(":memory:");
  const registry = new ProviderRegistry();
  for (const provider of VALIDATION_PROVIDERS) {
    registry.register(makeValidationAdapter(provider, onValidate));
  }
  const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
  const auth = new AuthService(vault);
  const app = createServer(vault, poller, registry, auth, options);
  return { vault, registry, poller, auth, app };
}

async function register(
  auth: AuthService,
  email: string,
): Promise<{ id: string; cookie: string }> {
  const result = await auth.register(email, "Password12345678!");
  if (!result.success) throw new Error("Synthetic manual OAuth test user registration failed");
  return {
    id: result.data.user.id,
    cookie: `usage_session=${encodeURIComponent(result.data.token)}`,
  };
}

async function initiateManual(
  app: AppInstance,
  cookie: string,
  flow: ManualFlow,
): Promise<OAuthInitiationData> {
  const response = await app.request(flow.endpoint, {
    method: "POST",
    headers: { Cookie: cookie },
  });
  const body = await response.json() as { success: boolean; data?: OAuthInitiationData };
  expect(response.status).toBe(200);
  expect(body.success).toBe(true);
  if (!body.data) throw new Error(`Synthetic ${flow.id} OAuth initiation returned no data`);
  return body.data;
}

async function initiateGoogle(app: AppInstance, cookie: string): Promise<OAuthInitiationData> {
  const response = await app.request("/api/oauth/google/initiate", {
    method: "POST",
    headers: { Cookie: cookie },
  });
  const body = await response.json() as { success: boolean; data?: OAuthInitiationData };
  expect(response.status).toBe(200);
  expect(body.success).toBe(true);
  if (!body.data) throw new Error("Synthetic Google OAuth initiation returned no data");
  return body.data;
}

async function postManual(
  app: AppInstance,
  cookie: string,
  sessionId: string,
  callbackInput: unknown,
): Promise<Response> {
  return app.request("/api/oauth/manual", {
    method: "POST",
    headers: { Cookie: cookie, "Content-Type": "application/json" },
    body: JSON.stringify({ sessionId, callbackInput }),
  });
}

async function status(app: AppInstance, cookie: string, sessionId: string): Promise<Response> {
  return app.request(`/api/oauth/status/${encodeURIComponent(sessionId)}`, {
    headers: { Cookie: cookie },
  });
}

interface OwnedSession {
  cookie: string;
  sessionId: string;
}

async function cancelSessions(app: AppInstance, sessions: readonly OwnedSession[]): Promise<void> {
  for (const session of sessions) {
    await Promise.resolve(app.request(`/api/oauth/sessions/${encodeURIComponent(session.sessionId)}`, {
      method: "DELETE",
      headers: { Cookie: session.cookie },
    })).catch(() => undefined);
  }
}

function callbackUrl(redirectUri: string, state: string, code = "synthetic-oauth-code"): string {
  const callback = new URL(redirectUri);
  callback.searchParams.set("code", code);
  callback.searchParams.set("state", state);
  return callback.toString();
}

function validInput(flow: ManualFlow, data: OAuthInitiationData, code: string): string {
  if (!data.redirectUri) throw new Error(`Synthetic ${flow.id} initiation omitted redirectUri`);
  return callbackUrl(data.redirectUri, data.sessionId, code);
}

function assertManualInitiation(data: OAuthInitiationData, flow: ManualFlow): void {
  expect(data.manualCallback).toBe(true);
  expect(data.manualInput).toBe(flow.manualInput);
  expect(data.expiresIn).toBe(600);

  const authUrl = new URL(data.authUrl);
  const redirectUri = flow.redirectUri;
  if (!redirectUri || !data.redirectUri) {
    throw new Error(`Synthetic ${flow.id} initiation omitted redirectUri`);
  }
  const requestedRedirectUri = requiredString(authUrl.searchParams.get("redirect_uri"), `${flow.id} redirect_uri`);
  const state = requiredString(authUrl.searchParams.get("state"), `${flow.id} state`);
  expect(data.redirectUri).toBe(redirectUri);
  expect(requestedRedirectUri).toBe(redirectUri);
  expect(state).toBe(data.sessionId);
  if (flow.id === "claude") {
    expect(requiredString(authUrl.searchParams.get("code_challenge_method"), "Claude challenge method"))
      .toBe("S256");
    expect(requiredString(authUrl.searchParams.get("code_challenge"), "Claude challenge")).not.toBe("");
  } else {
    expect(authUrl.searchParams.has("code_challenge")).toBe(false);
    expect(authUrl.searchParams.has("code_challenge_method")).toBe(false);
  }
}

interface FetchCall {
  url: string;
  method: string;
  body: string;
  signal?: AbortSignal | null;
}

interface FetchHarness {
  calls: FetchCall[];
  restore(): void;
}

function installFetch(
  handler: (call: FetchCall) => Response | Promise<Response>,
): FetchHarness {
  const originalFetch = globalThis.fetch;
  const calls: FetchCall[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : undefined;
    const call: FetchCall = {
      url: request ? request.url : String(input),
      method: init?.method ?? request?.method ?? "GET",
      body: typeof init?.body === "string" ? init.body : "",
      signal: init?.signal ?? request?.signal,
    };
    calls.push(call);
    return handler(call);
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = originalFetch; } };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function installProviderResponses(): FetchHarness {
  return installFetch(call => {
    switch (call.url) {
      case "https://api.anthropic.com/v1/oauth/token":
        return jsonResponse({ access_token: "synthetic-claude-access", refresh_token: "synthetic-claude-refresh" });
      case "https://api.anthropic.com/api/oauth/user_profile":
        return jsonResponse({ email: "claude@example.test" });
      case "https://oauth2.googleapis.com/token":
        return jsonResponse({ access_token: "synthetic-gemini-access", refresh_token: "synthetic-gemini-refresh" });
      case "https://www.googleapis.com/oauth2/v1/userinfo?alt=json":
        return jsonResponse({ email: "gemini@example.test" });
      case "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist":
        return jsonResponse({ cloudaicompanionProject: "synthetic-gemini-project" });
      case "https://zcode.z.ai/api/v1/oauth/token":
        return jsonResponse({
          zai: { access_token: "synthetic-zai-oauth-access" },
          user: { email: "zai@example.test", id: "synthetic-zai-account" },
        });
      case "https://api.z.ai/api/auth/z/login":
        return jsonResponse({ access_token: "synthetic-zai-business-access" });
      case "https://api.z.ai/api/biz/customer/getCustomerInfo":
        return jsonResponse({
          organizations: [{
            organizationId: "synthetic-zai-organization",
            isDefault: true,
            projects: [{ projectId: "synthetic-zai-project", isDefault: true }],
          }],
        });
      case "https://api.z.ai/api/biz/v1/organization/synthetic-zai-organization/projects/synthetic-zai-project/api_keys":
        return jsonResponse([{ name: "oh-my-pi", apiKey: "synthetic-zai-key-id" }]);
      case "https://api.z.ai/api/biz/v1/organization/synthetic-zai-organization/projects/synthetic-zai-project/api_keys/copy/synthetic-zai-key-id":
        return jsonResponse({ secretKey: "synthetic-zai-secret" });
      default:
        throw new Error(`Unexpected synthetic OAuth URL: ${call.url}`);
    }
  });
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonBody(call: FetchCall): Record<string, unknown> {
  const value: unknown = JSON.parse(call.body);
  if (!isJsonObject(value)) throw new Error("Synthetic provider response body is not an object");
  return value;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`Synthetic ${name} is missing`);
  return value;
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function snapshotGoogleEnv(): Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>> {
  const snapshot: Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>> = {};
  for (const key of GOOGLE_ENV_KEYS) snapshot[key] = process.env[key];
  return snapshot;
}

function restoreGoogleEnv(snapshot: Partial<Record<(typeof GOOGLE_ENV_KEYS)[number], string>>): void {
  for (const key of GOOGLE_ENV_KEYS) {
    const value = snapshot[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function useHostedEmbeddedGoogleClient(): void {
  process.env["NODE_ENV"] = "production";
  process.env["GOOGLE_OAUTH_CLIENT_ID"] = "";
  process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "";
  process.env["GOOGLE_OAUTH_REDIRECT_URI"] = GOOGLE_PUBLIC_CALLBACK;
  process.env["USAGE_MASTER_KEY"] = "synthetic-manual-google-master-key";
}

function useGoogleWebClient(): void {
  process.env["NODE_ENV"] = "production";
  process.env["GOOGLE_OAUTH_CLIENT_ID"] = "synthetic-web-client.apps.googleusercontent.com";
  process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "synthetic-web-client-secret";
  process.env["GOOGLE_OAUTH_REDIRECT_URI"] = GOOGLE_PUBLIC_CALLBACK;
  process.env["USAGE_MASTER_KEY"] = "synthetic-manual-google-master-key";
}

describe("listener-free manual OAuth callbacks", () => {
  it("requires authentication on the single generic callback endpoint", async () => {
    const { vault, app } = context();
    try {
      const response = await app.request("/api/oauth/manual", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: "unknown-session", callbackInput: "synthetic-code" }),
      });
      expect(response.status).toBe(401);
    } finally {
      vault.close();
    }
  });

  it("keeps each provider's pending sessions isolated for two simultaneously authenticated owners", async () => {
    const { vault, app, auth } = context();
    const unexpected = installFetch(call => {
      throw new Error(`Manual initiation or foreign submission made an upstream request: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const alice = await register(auth, "manual-oauth-alice@example.test");
      const bob = await register(auth, "manual-oauth-bob@example.test");

      for (const flow of MANUAL_FLOWS) {
        const [aliceData, bobData] = await Promise.all([
          initiateManual(app, alice.cookie, flow),
          initiateManual(app, bob.cookie, flow),
        ]);
        assertManualInitiation(aliceData, flow);
        assertManualInitiation(bobData, flow);
        expect(aliceData.sessionId).not.toBe(bobData.sessionId);
        sessions.push(
          { cookie: alice.cookie, sessionId: aliceData.sessionId },
          { cookie: bob.cookie, sessionId: bobData.sessionId },
        );

        const [alicePending, bobPending] = await Promise.all([
          status(app, alice.cookie, aliceData.sessionId),
          status(app, bob.cookie, bobData.sessionId),
        ]);
        expect(alicePending.status).toBe(200);
        expect(await alicePending.json()).toMatchObject({ status: "pending" });
        expect(bobPending.status).toBe(200);
        expect(await bobPending.json()).toMatchObject({ status: "pending" });
        expect((await status(app, bob.cookie, aliceData.sessionId)).status).toBe(404);
        expect((await status(app, alice.cookie, bobData.sessionId)).status).toBe(404);

        const foreignSubmission = await postManual(
          app,
          bob.cookie,
          aliceData.sessionId,
          validInput(flow, aliceData, `foreign-${flow.id}-code`),
        );
        expect(foreignSubmission.status).toBe(404);
        expect((await (await status(app, alice.cookie, aliceData.sessionId)).json() as { status: string }).status)
          .toBe("pending");
      }
      expect(unexpected.calls).toHaveLength(0);
    } finally {
      await cancelSessions(app, sessions);
      unexpected.restore();
      vault.close();
    }
  });

  it("keeps embedded Google manual sessions pending for two simultaneous owners", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    const { vault, app, auth } = context();
    const noNetwork = installFetch(call => {
      throw new Error(`Concurrent Google initiation reached provider exchange: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const alice = await register(auth, "manual-google-concurrent-alice@example.test");
      const bob = await register(auth, "manual-google-concurrent-bob@example.test");
      const [aliceData, bobData] = await Promise.all([
        initiateGoogle(app, alice.cookie),
        initiateGoogle(app, bob.cookie),
      ]);
      expect(aliceData.manualCallback).toBe(true);
      expect(aliceData.manualInput).toBe("url");
      expect(aliceData.sessionId).not.toBe(bobData.sessionId);
      sessions.push(
        { cookie: alice.cookie, sessionId: aliceData.sessionId },
        { cookie: bob.cookie, sessionId: bobData.sessionId },
      );

      for (const [owner, data] of [[alice, aliceData], [bob, bobData]] as const) {
        const pending = await status(app, owner.cookie, data.sessionId);
        expect(pending.status).toBe(200);
        expect(await pending.json()).toMatchObject({ status: "pending", provider: "antigravity" });
      }
      const foreign = await postManual(
        app,
        bob.cookie,
        aliceData.sessionId,
        callbackUrl(GOOGLE_LOOPBACK_CALLBACK, aliceData.sessionId),
      );
      expect(foreign.status).toBe(404);
      expect((await (await status(app, alice.cookie, aliceData.sessionId)).json() as { status: string }).status)
        .toBe("pending");
      expect(noNetwork.calls).toHaveLength(0);
    } finally {
      await cancelSessions(app, sessions);
      noNetwork.restore();
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("rejects malformed and ambiguous callback inputs before exchange", async () => {
    const { vault, app, auth } = context();
    const unexpected = installFetch(call => {
      throw new Error(`Invalid callback input reached provider exchange: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const users = new Map<ManualFlowId, { id: string; cookie: string }>();
      for (const flow of MANUAL_FLOWS) {
        users.set(flow.id, await register(auth, `manual-parser-${flow.id}@example.test`));
      }

      for (const flow of MANUAL_FLOWS) {
        const owner = users.get(flow.id)!;
        const data = await initiateManual(app, owner.cookie, flow);
        sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });
        assertManualInitiation(data, flow);

        const invalidInputs: unknown[] = [null, 7, { pasted: "not a string" }];
        const redirectUri = flow.redirectUri!;
        const expected = new URL(redirectUri);
        const wrongProtocol = new URL(redirectUri);
        wrongProtocol.protocol = "https:";
        const wrongHost = new URL(redirectUri);
        wrongHost.hostname = expected.hostname === "localhost" ? "127.0.0.1" : "localhost";
        const wrongPath = new URL(redirectUri);
        wrongPath.pathname = `${expected.pathname}/wrong`;
        const userInfo = new URL(redirectUri);
        userInfo.username = "untrusted";
        userInfo.password = "synthetic";
        const encodedState = encodeURIComponent(data.sessionId);
        const code = "synthetic-invalid-code";
        invalidInputs.push(
          "http://[",
          wrongProtocol.toString() + `?code=${code}&state=${encodedState}`,
          wrongHost.toString() + `?code=${code}&state=${encodedState}`,
          wrongPath.toString() + `?code=${code}&state=${encodedState}`,
          userInfo.toString() + `?code=${code}&state=${encodedState}`,
          `${callbackUrl(redirectUri, data.sessionId, code)}#unexpected-fragment`,
          `${redirectUri}?code=first&code=second&state=${encodedState}`,
          `${redirectUri}?code=${code}&state=${encodedState}&state=duplicate`,
          `${redirectUri}?code=${code}`,
          `${redirectUri}?code=${code}&state=wrong-state`,
          `${redirectUri}?code=${code}&error=access_denied&state=${encodedState}`,
          `${redirectUri}?state=${encodedState}`,
        );
        if (flow.id === "claude") {
          invalidInputs.push(
            "synthetic-claude-raw-code",
            "synthetic-claude-code#wrong-state",
            callbackUrl(MANUAL_FLOWS.find(candidate => candidate.id === "gemini-cli")!.redirectUri!, data.sessionId),
          );
        } else {
          invalidInputs.push("synthetic-raw-code", `synthetic-raw-code#${data.sessionId}`);
        }
        for (const callbackInput of invalidInputs) {
          const response = await postManual(app, owner.cookie, data.sessionId, callbackInput);
          expect(response.status).toBe(400);
        }
        const pending = await status(app, owner.cookie, data.sessionId);
        expect(pending.status).toBe(200);
        expect(await pending.json()).toMatchObject({ status: "pending" });
      }

      const malformedJson = await app.request("/api/oauth/manual", {
        method: "POST",
        headers: { Cookie: users.get("claude")!.cookie, "Content-Type": "application/json" },
        body: "{malformed-json",
      });
      expect(malformedJson.status).toBe(400);
      expect(unexpected.calls).toHaveLength(0);
    } finally {
      await cancelSessions(app, sessions);
      unexpected.restore();
      vault.close();
    }
  });

  it("consumes a state-bound provider denial without exchanging a code", async () => {
    const { vault, app, auth } = context();
    const noNetwork = installFetch(call => {
      throw new Error(`Provider denial reached exchange: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-oauth-provider-denial@example.test");
      const flow = MANUAL_FLOWS.find(candidate => candidate.id === "gemini-cli")!;
      const data = await initiateManual(app, owner.cookie, flow);
      sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });
      const callbackInput = `${flow.redirectUri!}?error=access_denied&state=${encodeURIComponent(data.sessionId)}`;
      const response = await postManual(app, owner.cookie, data.sessionId, callbackInput);
      expect(response.status).toBe(400);
      expect(await response.text()).not.toContain("access_denied");
      expect(await (await status(app, owner.cookie, data.sessionId)).json()).toMatchObject({
        status: "error",
        error: "Authorization was denied",
      });
      expect(noNetwork.calls).toHaveLength(0);
    } finally {
      await cancelSessions(app, sessions);
      noNetwork.restore();
      vault.close();
    }
  });

  it("preserves existing credentials and snapshots when any provider rejects a candidate", async () => {
    let failingProvider = "";
    const { vault, app, auth } = context({}, async credential => {
      if (credential.provider === failingProvider) {
        throw new Error("synthetic candidate validation failure");
      }
    });
    const upstream = installProviderResponses();
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-oauth-preserve-owner@example.test");
      const otherOwner = await register(auth, "manual-oauth-preserve-other@example.test");
      const labels: Record<ManualFlowId, string> = {
        claude: "claude@example.test",
        "gemini-cli": "gemini@example.test",
        zai: "zai@example.test",
      };

      for (const flow of MANUAL_FLOWS) {
        const previous = vault.saveCredential(owner.id, {
          ownerId: owner.id,
          provider: flow.provider,
          accountLabel: labels[flow.id],
          accent: "violet",
          credentialType: flow.id === "claude" || flow.id === "gemini-cli" ? "oauth" : "api_key",
          secret: `synthetic-${flow.id}-original-secret`,
          metadata: {
            refreshToken: `synthetic-${flow.id}-original-refresh`,
            preservationMarker: `original-${flow.id}`,
          },
        });
        const originalSnapshot: UsageReport = {
          ownerId: owner.id,
          provider: flow.provider,
          credentialId: previous.id,
          accountLabel: previous.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          stale: false,
          source: "live",
        };
        expect(vault.saveSnapshot(owner.id, originalSnapshot)).toBe(true);
        const historyBefore = vault.getSnapshotHistory(owner.id, flow.provider, 24);

        const data = await initiateManual(app, owner.cookie, flow);
        sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });
        failingProvider = flow.provider;
        const callbackInput = validInput(flow, data, `synthetic-${flow.id}-candidate-code`);
        const rejected = await postManual(app, owner.cookie, data.sessionId, callbackInput);
        expect(rejected.status).toBe(400);
        expect(await (await status(app, owner.cookie, data.sessionId)).json()).toMatchObject({ status: "error" });

        expect(vault.getCredential(owner.id, previous.id)).toEqual(previous);
        expect(vault.listCredentials(owner.id, flow.provider)).toEqual([previous]);
        expect(vault.getSnapshotHistory(owner.id, flow.provider, 24)).toEqual(historyBefore);
        expect(vault.listCredentials(otherOwner.id, flow.provider)).toHaveLength(0);
      }
    } finally {
      await cancelSessions(app, sessions);
      upstream.restore();
      vault.close();
    }
  });

  it("completes Claude from the full registered callback URL", async () => {
    const { vault, app, auth } = context();
    const upstream = installProviderResponses();
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-oauth-claude-full-url@example.test");
      const flow = MANUAL_FLOWS.find(candidate => candidate.id === "claude")!;
      const data = await initiateManual(app, owner.cookie, flow);
      sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });
      const redirectUri = requiredString(data.redirectUri, "Claude redirect URI");
      const callbackInput = callbackUrl(redirectUri, data.sessionId, "synthetic-claude-full-url-code");
      const response = await postManual(app, owner.cookie, data.sessionId, callbackInput);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ success: true });

      const tokenCall = upstream.calls.find(call => call.url === "https://api.anthropic.com/v1/oauth/token");
      if (!tokenCall) throw new Error("Synthetic Claude full-URL exchange was not captured");
      const tokenBody = parseJsonBody(tokenCall);
      expect(requiredString(tokenBody["code"], "Claude callback code")).toBe("synthetic-claude-full-url-code");
      expect(requiredString(tokenBody["redirect_uri"], "Claude token redirect URI")).toBe(redirectUri);
      expect(new URL(callbackInput).searchParams.get("state")).toBe(data.sessionId);
    } finally {
      await cancelSessions(app, sessions);
      upstream.restore();
      vault.close();
    }
  });

  it("completes all three manual provider routes and preserves PKCE verifier continuity", async () => {
    const { vault, app, auth } = context();
    const upstream = installProviderResponses();
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-oauth-complete@example.test");
      const issuedCodes = new Map<ManualFlowId, string>([
        ["claude", "synthetic-claude-callback-code"],
        ["gemini-cli", "synthetic-gemini-callback-code"],
        ["zai", "synthetic-zai-callback-code"],
      ]);
      const completions = new Map<ManualFlowId, { data: OAuthInitiationData; input: string }>();

      for (const flow of MANUAL_FLOWS) {
        const data = await initiateManual(app, owner.cookie, flow);
        sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });
        assertManualInitiation(data, flow);
        const code = requiredString(issuedCodes.get(flow.id), `${flow.id} authorization code`);
        const input = flow.id === "claude"
          ? `${code}#${data.sessionId}`
          : validInput(flow, data, code);

        const response = await postManual(app, owner.cookie, data.sessionId, input);
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ success: true });
        expect(await (await status(app, owner.cookie, data.sessionId)).json()).toMatchObject({ status: "complete" });
        completions.set(flow.id, { data, input });
      }

      const claude = completions.get("claude")!;
      const claudeAuth = new URL(claude.data.authUrl);
      expect(claudeAuth.searchParams.get("code_challenge_method")).toBe("S256");
      const claudeTokenCall = upstream.calls.find(call => call.url === "https://api.anthropic.com/v1/oauth/token");
      if (!claudeTokenCall) throw new Error("Synthetic Claude token request was not captured");
      const claudeTokenBody = parseJsonBody(claudeTokenCall);
      expect(claudeTokenBody["code"]).toBe(requiredString(issuedCodes.get("claude"), "Claude authorization code"));
      const claudeVerifier = requiredString(claudeTokenBody["code_verifier"], "Claude code verifier");
      const claudeChallenge = requiredString(claudeAuth.searchParams.get("code_challenge"), "Claude challenge");
      expect(pkceChallenge(claudeVerifier)).toBe(claudeChallenge);
      expect(claudeTokenBody["redirect_uri"]).toBe("http://localhost:54545/callback");


      const gemini = completions.get("gemini-cli")!;
      const geminiAuth = new URL(gemini.data.authUrl);
      const geminiCall = upstream.calls.find(call => call.url === "https://oauth2.googleapis.com/token");
      if (!geminiCall) throw new Error("Synthetic Gemini token request was not captured");
      const geminiBody = new URLSearchParams(geminiCall.body);
      expect(requiredString(geminiBody.get("code"), "Gemini authorization code"))
        .toBe(requiredString(issuedCodes.get("gemini-cli"), "Gemini initiated code"));
      expect(requiredString(geminiBody.get("client_id"), "Gemini token client"))
        .toBe(requiredString(geminiAuth.searchParams.get("client_id"), "Gemini authorization client"));
      expect(requiredString(geminiBody.get("redirect_uri"), "Gemini token redirect URI"))
        .toBe(requiredString(gemini.data.redirectUri, "Gemini initiated redirect URI"));
      expect(requiredString(geminiAuth.searchParams.get("state"), "Gemini authorization state"))
        .toBe(gemini.data.sessionId);

      const zai = completions.get("zai")!;
      const zaiAuth = new URL(zai.data.authUrl);
      const zaiCall = upstream.calls.find(call => call.url === "https://zcode.z.ai/api/v1/oauth/token");
      if (!zaiCall) throw new Error("Synthetic Z.ai token request was not captured");
      const zaiBody = parseJsonBody(zaiCall);
      expect(zaiBody["code"]).toBe(requiredString(issuedCodes.get("zai"), "Z.ai authorization code"));
      expect(zaiBody["provider"]).toBe("zai");
      expect(zaiBody["redirect_uri"]).toBe(requiredString(zai.data.redirectUri, "Z.ai initiated redirect URI"));
      expect(zaiBody["state"]).toBe(zai.data.sessionId);
      expect(requiredString(zaiAuth.searchParams.get("state"), "Z.ai authorization state"))
        .toBe(zai.data.sessionId);
      expect(requiredString(zaiAuth.searchParams.get("redirect_uri"), "Z.ai authorization redirect URI"))
        .toBe(requiredString(zai.data.redirectUri, "Z.ai initiated redirect URI"));

      const expectedCredentials = [
        { provider: "anthropic", label: "claude@example.test", secret: "synthetic-claude-access" },
        { provider: "google-gemini-cli", label: "gemini@example.test", secret: "synthetic-gemini-access" },
        { provider: "zai", label: "zai@example.test", secret: "synthetic-zai-key-id.synthetic-zai-secret" },
      ];
      for (const expected of expectedCredentials) {
        const credentials = vault.listCredentials(owner.id, expected.provider);
        expect(credentials).toHaveLength(1);
        expect(credentials[0]).toMatchObject({
          ownerId: owner.id,
          provider: expected.provider,
          accountLabel: expected.label,
          secret: expected.secret,
        });
        expect(vault.getSnapshotHistory(owner.id, expected.provider, 24)).toHaveLength(1);
      }

      const callsBeforeReplay = upstream.calls.length;
      for (const flow of MANUAL_FLOWS) {
        const completion = completions.get(flow.id)!;
        const replay = await postManual(app, owner.cookie, completion.data.sessionId, completion.input);
        expect(replay.status).not.toBe(200);
      }
      expect(upstream.calls).toHaveLength(callsBeforeReplay);
    } finally {
      await cancelSessions(app, sessions);
      upstream.restore();
      vault.close();
    }
  });

  it("rejects unknown, foreign, cancelled, and expired sessions before outbound fetch", async () => {
    let now = 1_800_000_000_000;
    const { vault, app, auth } = context({ oauthNow: () => now });
    const unexpected = installFetch(call => {
      throw new Error(`Rejected manual callback reached provider exchange: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-oauth-deadline-owner@example.test");
      const foreign = await register(auth, "manual-oauth-deadline-foreign@example.test");
      const cancelData = await initiateManual(app, owner.cookie, MANUAL_FLOWS[0]!);
      sessions.push({ cookie: owner.cookie, sessionId: cancelData.sessionId });
      const unknown = await postManual(app, owner.cookie, "unknown-manual-session", validInput(MANUAL_FLOWS[0]!, cancelData, "unknown-code"));
      expect(unknown.status).toBe(404);
      const foreignAttempt = await postManual(app, foreign.cookie, cancelData.sessionId, validInput(MANUAL_FLOWS[0]!, cancelData, "foreign-code"));
      expect(foreignAttempt.status).toBe(404);
      const foreignCancel = await app.request(`/api/oauth/sessions/${encodeURIComponent(cancelData.sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: foreign.cookie },
      });
      expect(foreignCancel.status).toBe(404);
      expect((await (await status(app, owner.cookie, cancelData.sessionId)).json() as { status: string }).status)
        .toBe("pending");

      const cancelled = await app.request(`/api/oauth/sessions/${encodeURIComponent(cancelData.sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: owner.cookie },
      });
      expect(cancelled.status).toBe(200);
      const afterCancel = await postManual(
        app,
        owner.cookie,
        cancelData.sessionId,
        validInput(MANUAL_FLOWS[0]!, cancelData, "cancelled-code"),
      );
      expect(afterCancel.status).not.toBe(200);
      expect(vault.getSnapshotHistory(owner.id, MANUAL_FLOWS[0]!.provider, 24)).toHaveLength(0);

      const expiredFlow = MANUAL_FLOWS[1]!;
      const expiredData = await initiateManual(app, owner.cookie, expiredFlow);
      sessions.push({ cookie: owner.cookie, sessionId: expiredData.sessionId });
      now += 10 * 60 * 1000;
      const afterExpiry = await postManual(
        app,
        owner.cookie,
        expiredData.sessionId,
        validInput(expiredFlow, expiredData, "expired-code"),
      );
      expect(afterExpiry.status).not.toBe(200);
      expect(vault.listCredentials(owner.id)).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, expiredFlow.provider, 24)).toHaveLength(0);
      expect(unexpected.calls).toHaveLength(0);
    } finally {
      await cancelSessions(app, sessions);
      unexpected.restore();
      vault.close();
    }
  });


  it("migrates embedded Google manual completion to the generic endpoint", async () => {
    const env = snapshotGoogleEnv();
    useHostedEmbeddedGoogleClient();
    let exchange: { code: string; verifier: string; config?: Partial<GoogleOAuthConfig> } | undefined;
    const { vault, app, auth } = context({
      googleOAuthExchange: async (code, verifier, config): Promise<GoogleTokenResult> => {
        exchange = { code, verifier, config };
        return {
          accessToken: "synthetic-embedded-google-access",
          refreshToken: "synthetic-embedded-google-refresh",
          email: "embedded-google@example.test",
        };
      },
    });
    const noNetwork = installFetch(call => {
      throw new Error(`Embedded Google manual flow made an unexpected fetch: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-embedded-google@example.test");
      const data = await initiateGoogle(app, owner.cookie);
      expect(data.manualCallback).toBe(true);
      expect(data.manualInput).toBe("url");
      expect(data.redirectUri).toBe(GOOGLE_LOOPBACK_CALLBACK);
      expect(new URL(data.authUrl).searchParams.get("redirect_uri")).toBe(GOOGLE_LOOPBACK_CALLBACK);
      expect(new URL(data.authUrl).searchParams.get("state")).toBe(data.sessionId);
      sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });

      const input = callbackUrl(GOOGLE_LOOPBACK_CALLBACK, data.sessionId, "synthetic-embedded-google-code");
      const response = await postManual(app, owner.cookie, data.sessionId, input);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ success: true });
      expect(exchange).toMatchObject({
        code: "synthetic-embedded-google-code",
        config: { redirectUri: GOOGLE_LOOPBACK_CALLBACK },
      });
      expect(exchange?.verifier).toBeTruthy();
      expect(vault.listCredentials(owner.id, "antigravity")).toHaveLength(1);
      expect(vault.listCredentials(owner.id, "antigravity")[0]).toMatchObject({
        accountLabel: "embedded-google@example.test",
        secret: "synthetic-embedded-google-access",
      });
      expect(vault.getSnapshotHistory(owner.id, "antigravity", 24)).toHaveLength(1);
      expect(noNetwork.calls).toHaveLength(0);

      const replay = await postManual(app, owner.cookie, data.sessionId, input);
      expect(replay.status).not.toBe(200);
      expect(exchange?.code).toBe("synthetic-embedded-google-code");
    } finally {
      await cancelSessions(app, sessions);
      noNetwork.restore();
      vault.close();
      restoreGoogleEnv(env);
    }
  });

  it("keeps the custom Google Web-client public callback flow working", async () => {
    const env = snapshotGoogleEnv();
    useGoogleWebClient();
    let exchange: { code: string; verifier: string; config?: Partial<GoogleOAuthConfig> } | undefined;
    const { vault, app, auth } = context({
      googleOAuthExchange: async (code, verifier, config): Promise<GoogleTokenResult> => {
        exchange = { code, verifier, config };
        return {
          accessToken: "synthetic-web-google-access",
          refreshToken: "synthetic-web-google-refresh",
          email: "web-google@example.test",
        };
      },
    });
    const noNetwork = installFetch(call => {
      throw new Error(`Google Web callback made an unexpected fetch: ${call.url}`);
    });
    const sessions: OwnedSession[] = [];
    try {
      const owner = await register(auth, "manual-web-google@example.test");
      const data = await initiateGoogle(app, owner.cookie);
      expect(data.manualCallback).toBe(false);
      expect(data.redirectUri).toBe(GOOGLE_PUBLIC_CALLBACK);
      expect(new URL(data.authUrl).searchParams.get("redirect_uri")).toBe(GOOGLE_PUBLIC_CALLBACK);
      expect(data.manualInput).not.toBe("url");
      sessions.push({ cookie: owner.cookie, sessionId: data.sessionId });

      const callbackParams = new URLSearchParams({
        code: "synthetic-web-google-code",
        state: data.sessionId,
      });
      const callback = await app.request(`/api/oauth/google/callback?${callbackParams.toString()}`);
      expect(callback.status).toBe(200);
      expect(await callback.text()).toContain("Google Login Successful");
      expect(exchange).toMatchObject({
        code: "synthetic-web-google-code",
        config: {
          clientId: "synthetic-web-client.apps.googleusercontent.com",
          clientSecret: "synthetic-web-client-secret",
          redirectUri: GOOGLE_PUBLIC_CALLBACK,
        },
      });
      expect(vault.listCredentials(owner.id, "antigravity")).toHaveLength(1);
      expect(vault.listCredentials(owner.id, "antigravity")[0]).toMatchObject({
        accountLabel: "web-google@example.test",
        secret: "synthetic-web-google-access",
      });
      expect(vault.getSnapshotHistory(owner.id, "antigravity", 24)).toHaveLength(1);
      expect(noNetwork.calls).toHaveLength(0);

      const replay = await app.request(`/api/oauth/google/callback?${callbackParams.toString()}`);
      expect(replay.status).toBe(400);
    } finally {
      await cancelSessions(app, sessions);
      noNetwork.restore();
      vault.close();
      restoreGoogleEnv(env);
    }
  });
});

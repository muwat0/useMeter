import { describe, expect, it } from "bun:test";
import { AuthService } from "../src/core/auth/auth";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import { PollerEngine } from "../src/core/poller/poller";
import { StorageVault } from "../src/core/storage/vault";
import { exchangeOpenRouterCode } from "../src/core/oauth/openrouter";
import { createServer, type AppInstance, type ServerOptions } from "../src/server/app";
import type { StoredCredential, UsageReport } from "../src/types";

const CALLBACK_PATH = "/api/oauth/openrouter/callback";
const TEST_ORIGIN = "https://usemeter.example.test";
const TEST_CALLBACK = `${TEST_ORIGIN}${CALLBACK_PATH}`;
const TEST_PASSWORD = "Password12345678!";

type Exchange = NonNullable<ServerOptions["openRouterOAuthExchange"]>;
type ValidationHook = (credential: StoredCredential) => void | Promise<void>;

interface InitiationData {
  authUrl: string;
  sessionId: string;
  expiresIn: number;
  manualCallback: boolean;
  manualInput?: string;
}

function context(options: ServerOptions = {}, onValidate?: ValidationHook) {
  const vault = new StorageVault(":memory:");
  const registry = new ProviderRegistry();
  const adapter: ProviderAdapter = {
    id: "synthetic-openrouter",
    supports: provider => provider === "openrouter",
    async fetchUsage(credential): Promise<UsageReport> {
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
  registry.register(adapter);
  const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
  const auth = new AuthService(vault);
  const app = createServer(vault, poller, registry, auth, options);
  return { vault, registry, poller, auth, app };
}

async function register(
  auth: AuthService,
  email: string,
): Promise<{ id: string; cookie: string }> {
  const result = await auth.register(email, TEST_PASSWORD);
  if (!result.success) throw new Error("Synthetic OpenRouter OAuth test user registration failed");
  return {
    id: result.data.user.id,
    cookie: `usage_session=${encodeURIComponent(result.data.token)}`,
  };
}

async function initiate(
  app: AppInstance,
  cookie: string,
  requestUrl = "/api/oauth/openrouter/initiate",
  additionalHeaders: Record<string, string> = {},
): Promise<InitiationData> {
  const response = await app.request(requestUrl, {
    method: "POST",
    headers: { Cookie: cookie, ...additionalHeaders },
  });
  const body = await response.json() as { success: boolean; data?: InitiationData; error?: string };
  if (!response.ok || !body.data) {
    throw new Error(`Synthetic OpenRouter initiation failed: ${response.status} ${body.error ?? ""}`);
  }
  return body.data;
}

function callbackUrl(data: InitiationData, code = "synthetic-openrouter-code"): string {
  const callback = new URL(new URL(data.authUrl).searchParams.get("callback_url")!);
  callback.searchParams.set("code", code);
  callback.searchParams.set("state", data.sessionId);
  return callback.toString();
}

async function status(app: AppInstance, cookie: string, sessionId: string): Promise<Response> {
  return app.request(`/api/oauth/status/${encodeURIComponent(sessionId)}`, {
    headers: { Cookie: cookie },
  });
}

async function cancel(app: AppInstance, cookie: string, sessionId: string): Promise<Response> {
  return app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
    headers: { Cookie: cookie },
  });
}

function successExchange(
  onExchange?: (code: string, verifier: string, signal?: AbortSignal) => void,
): Exchange {
  return async (code, verifier, signal) => {
    onExchange?.(code, verifier, signal);
    return { apiKey: "synthetic-openrouter-api-key", label: "openrouter@example.test" };
  };
}

describe("OpenRouter automatic OAuth callback", () => {
  it("completes a same-origin PKCE callback without login cookie or pasted code and rejects replay", async () => {
    const calls: Array<{ code: string; verifier: string; signal?: AbortSignal }> = [];
    const { vault, app, auth } = context({
      openRouterOAuthExchange: successExchange((code, verifier, signal) => calls.push({ code, verifier, signal })),
    });
    try {
      const owner = await register(auth, "openrouter-callback-owner@example.test");
      const other = await register(auth, "openrouter-callback-other@example.test");
      const data = await initiate(app, owner.cookie, `${TEST_ORIGIN}/api/oauth/openrouter/initiate`);
      const authUrl = new URL(data.authUrl);
      const callback = authUrl.searchParams.get("callback_url");

      expect(data.manualCallback).toBe(false);
      expect(data.manualInput).toBeUndefined();
      expect(callback).toBe(TEST_CALLBACK);
      expect(authUrl.searchParams.get("state")).toBe(data.sessionId);
      expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]+$/);

      const oldPasteRoute = await app.request("/api/oauth/manual", {
        method: "POST",
        headers: { Cookie: owner.cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: data.sessionId, callbackInput: "synthetic-pasted-code" }),
      });
      expect(oldPasteRoute.status).toBe(404);
      expect((await status(app, other.cookie, data.sessionId)).status).toBe(404);
      expect((await cancel(app, other.cookie, data.sessionId)).status).toBe(404);

      const query = new URLSearchParams({ state: "unknown-state", code: "synthetic-unknown-code" });
      expect((await app.request(`${CALLBACK_PATH}?${query}`)).status).toBe(400);
      expect(calls).toHaveLength(0);

      const callbackResponse = await app.request(callbackUrl(data), { method: "GET" });
      expect(callbackResponse.status).toBe(200);
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({ code: "synthetic-openrouter-code" });
      expect(calls[0]?.verifier).not.toBe("");
      expect(calls[0]?.signal?.aborted).toBe(true);
      const challenge = authUrl.searchParams.get("code_challenge")!;
      const derivedChallenge = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(calls[0]!.verifier),
      );
      const challengeBase64 = Buffer.from(derivedChallenge).toString("base64url");
      expect(challengeBase64).toBe(challenge);

      expect(await (await status(app, owner.cookie, data.sessionId)).json()).toMatchObject({
        status: "complete",
        provider: "openrouter",
        accountLabel: "openrouter@example.test",
      });
      expect(vault.listCredentials(owner.id, "openrouter")).toMatchObject([
        {
          ownerId: owner.id,
          provider: "openrouter",
          accountLabel: "openrouter@example.test",
          credentialType: "api_key",
          secret: "synthetic-openrouter-api-key",
          metadata: { source: "oauth-pkce" },
        },
      ]);
      expect(vault.listCredentials(other.id, "openrouter")).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, "openrouter", 24)).toHaveLength(1);

      const replay = await app.request(callbackUrl(data), { method: "GET" });
      expect(replay.status).toBe(400);
      expect(calls).toHaveLength(1);
      expect(vault.getSnapshotHistory(owner.id, "openrouter", 24)).toHaveLength(1);
    } finally {
      vault.close();
    }
  });

  it("honors trusted TLS-termination headers only when TRUST_PROXY is enabled and binds callbacks to that origin", async () => {
    const previousTrustProxy = process.env["TRUST_PROXY"];
    let exchangeCalls = 0;
    const { vault, app, auth } = context({
      openRouterOAuthExchange: successExchange(() => { exchangeCalls++; }),
    });
    try {
      const owner = await register(auth, "openrouter-proxy-owner@example.test");
      delete process.env["TRUST_PROXY"];
      const untrustedForwarded = await app.request("http://internal:3100/api/oauth/openrouter/initiate", {
        method: "POST",
        headers: {
          Cookie: owner.cookie,
          "X-Forwarded-Proto": "https",
          "X-Forwarded-Host": "attacker.example.test",
        },
      });
      expect(untrustedForwarded.status).toBe(400);

      process.env["TRUST_PROXY"] = "true";
      const headers = {
        Cookie: owner.cookie,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "usemeter.example.test",
      };
      const originSpoof = await app.request("http://internal:3100/api/oauth/openrouter/initiate", {
        method: "POST",
        headers: { ...headers, Origin: "https://attacker.example.test" },
      });
      expect(originSpoof.status).toBe(403);

      const data = await initiate(
        app,
        owner.cookie,
        "http://internal:3100/api/oauth/openrouter/initiate",
        {
          "X-Forwarded-Proto": "https",
          "X-Forwarded-Host": "usemeter.example.test",
        },
      );
      expect(new URL(data.authUrl).searchParams.get("callback_url")).toBe(TEST_CALLBACK);

      const callback = new URL(callbackUrl(data));
      const callbackQuery = callback.search;
      const wrongOrigin = await app.request(`http://internal:3100${CALLBACK_PATH}${callbackQuery}`, {
        headers: {
          "X-Forwarded-Proto": "https",
          "X-Forwarded-Host": "other.example.test",
        },
      });
      expect(wrongOrigin.status).toBe(400);
      expect(exchangeCalls).toBe(0);
      expect(await (await status(app, owner.cookie, data.sessionId)).json()).toMatchObject({ status: "pending" });

      const validCallback = await app.request(`http://internal:3100${CALLBACK_PATH}${callbackQuery}`, {
        headers: {
          "X-Forwarded-Proto": "https",
          "X-Forwarded-Host": "usemeter.example.test",
        },
      });
      expect(validCallback.status).toBe(200);
      expect(exchangeCalls).toBe(1);
    } finally {
      vault.close();
      if (previousTrustProxy === undefined) delete process.env["TRUST_PROXY"];
      else process.env["TRUST_PROXY"] = previousTrustProxy;
    }
  });

  it("rejects duplicate, denied, cancelled, and expired callbacks before token exchange", async () => {
    let now = 1_800_000_000_000;
    let exchangeCalls = 0;
    const { vault, app, auth } = context({
      oauthNow: () => now,
      openRouterOAuthExchange: successExchange(() => { exchangeCalls++; }),
    });
    try {
      const owner = await register(auth, "openrouter-invalid-callback-owner@example.test");
      const duplicateData = await initiate(app, owner.cookie);
      const duplicate = new URL(callbackUrl(duplicateData));
      duplicate.searchParams.append("state", "duplicate-state");
      expect((await app.request(duplicate.toString())).status).toBe(400);
      expect(await (await status(app, owner.cookie, duplicateData.sessionId)).json()).toMatchObject({ status: "pending" });

      const deniedData = await initiate(app, owner.cookie);
      const denied = new URL(new URL(deniedData.authUrl).searchParams.get("callback_url")!);
      denied.searchParams.set("state", deniedData.sessionId);
      denied.searchParams.set("error", "access_denied");
      const deniedResponse = await app.request(denied.toString());
      expect(deniedResponse.status).toBe(200);
      expect(await deniedResponse.text()).toContain("Authorization was denied");
      expect(await (await status(app, owner.cookie, deniedData.sessionId)).json()).toMatchObject({ status: "error" });

      const cancelledData = await initiate(app, owner.cookie);
      expect((await cancel(app, owner.cookie, cancelledData.sessionId)).status).toBe(200);
      expect((await app.request(callbackUrl(cancelledData))).status).toBe(400);

      const expiredData = await initiate(app, owner.cookie);
      now += 10 * 60 * 1_000 + 1;
      expect((await app.request(callbackUrl(expiredData))).status).toBe(400);
      expect(await (await status(app, owner.cookie, expiredData.sessionId)).json()).toMatchObject({ status: "error" });
      expect(exchangeCalls).toBe(0);
      expect(vault.listCredentials(owner.id, "openrouter")).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, "openrouter", 24)).toHaveLength(0);
    } finally {
      vault.close();
    }
  });

  it("claims once and prevents persistence when cancellation interrupts token exchange", async () => {
    const exchangeStarted = Promise.withResolvers<void>();
    const exchangeResult = Promise.withResolvers<{ apiKey: string; label?: string }>();
    let exchangeCalls = 0;
    let validations = 0;
    const exchange: Exchange = async (_code, _verifier, signal) => {
      exchangeCalls++;
      exchangeStarted.resolve();
      await exchangeResult.promise;
      expect(signal?.aborted).toBe(true);
      return { apiKey: "synthetic-late-openrouter-key" };
    };
    const { vault, app, auth } = context({ openRouterOAuthExchange: exchange }, async () => { validations++; });
    let callback: Promise<Response> | undefined;
    try {
      const owner = await register(auth, "openrouter-exchange-cancel-owner@example.test");
      const data = await initiate(app, owner.cookie);
      const url = callbackUrl(data);
      callback = Promise.resolve(app.request(url, { method: "GET" }));
      await exchangeStarted.promise;

      expect((await app.request(url, { method: "GET" })).status).toBe(400);
      expect(exchangeCalls).toBe(1);
      expect((await cancel(app, owner.cookie, data.sessionId)).status).toBe(200);
      exchangeResult.resolve({ apiKey: "synthetic-late-openrouter-key" });
      await callback;
      expect((await status(app, owner.cookie, data.sessionId)).status).toBe(404);
      expect((await app.request(url, { method: "GET" })).status).toBe(400);
      expect(validations).toBe(0);
      expect(vault.listCredentials(owner.id, "openrouter")).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, "openrouter", 24)).toHaveLength(0);
    } finally {
      exchangeResult.resolve({ apiKey: "synthetic-cleanup-openrouter-key" });
      await callback?.catch(() => undefined);
      vault.close();
    }
  });

  it("does not commit when cancellation occurs during provider validation", async () => {
    const validationStarted = Promise.withResolvers<void>();
    const validationGate = Promise.withResolvers<void>();
    const { vault, app, auth } = context({
      openRouterOAuthExchange: successExchange(),
    }, async () => {
      validationStarted.resolve();
      await validationGate.promise;
    });
    let callback: Promise<Response> | undefined;
    let validationReleased = false;
    try {
      const owner = await register(auth, "openrouter-validation-cancel-owner@example.test");
      const data = await initiate(app, owner.cookie);
      callback = Promise.resolve(app.request(callbackUrl(data), { method: "GET" }));
      await validationStarted.promise;
      expect((await cancel(app, owner.cookie, data.sessionId)).status).toBe(200);
      validationGate.resolve();
      validationReleased = true;
      await callback;
      expect((await status(app, owner.cookie, data.sessionId)).status).toBe(404);
      expect((await app.request(callbackUrl(data), { method: "GET" })).status).toBe(400);
      expect(vault.listCredentials(owner.id, "openrouter")).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, "openrouter", 24)).toHaveLength(0);
    } finally {
      if (!validationReleased) validationGate.resolve();
      await callback?.catch(() => undefined);
      vault.close();
    }
  });

  it("rechecks the deadline at the irreversible credential commit boundary", async () => {
    let now = 1_800_000_000_000;
    const validationStarted = Promise.withResolvers<void>();
    const validationGate = Promise.withResolvers<void>();
    const { vault, app, auth } = context({
      oauthNow: () => now,
      openRouterOAuthExchange: successExchange(),
    }, async () => {
      validationStarted.resolve();
      await validationGate.promise;
    });
    let callback: Promise<Response> | undefined;
    let validationReleased = false;
    try {
      const owner = await register(auth, "openrouter-deadline-owner@example.test");
      const data = await initiate(app, owner.cookie);
      callback = Promise.resolve(app.request(callbackUrl(data), { method: "GET" }));
      await validationStarted.promise;
      now += 10 * 60 * 1_000 + 1;
      validationGate.resolve();
      validationReleased = true;
      await callback;
      expect(await (await status(app, owner.cookie, data.sessionId)).json()).toMatchObject({
        status: "error",
        error: "Authorization session expired",
      });
      expect((await app.request(callbackUrl(data), { method: "GET" })).status).toBe(400);
      expect(vault.listCredentials(owner.id, "openrouter")).toHaveLength(0);
      expect(vault.getSnapshotHistory(owner.id, "openrouter", 24)).toHaveLength(0);
    } finally {
      if (!validationReleased) validationGate.resolve();
      await callback?.catch(() => undefined);
      vault.close();
    }
  });

  it("exchanges OpenRouter PKCE codes through deterministic fetch responses", async () => {
    const previousFetch = globalThis.fetch;
    const controller = new AbortController();
    const calls: Array<{ url: string; method: string; headers: Headers; body: string; signal?: AbortSignal | null }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : undefined;
      const url = request ? request.url : String(input);
      const headers = new Headers(init?.headers ?? request?.headers);
      const method = init?.method ?? request?.method ?? "GET";
      const body = typeof init?.body === "string" ? init.body : "";
      const signal = init?.signal ?? request?.signal;
      calls.push({ url, method, headers, body, signal });
      if (url === "https://openrouter.ai/api/v1/auth/keys") {
        return new Response(JSON.stringify({ key: "synthetic-fetched-openrouter-key" }), { status: 200 });
      }
      if (url === "https://openrouter.ai/api/v1/auth/key") {
        return new Response(JSON.stringify({ data: { label: "synthetic-openrouter-label" } }), { status: 200 });
      }
      throw new Error(`Unexpected synthetic OpenRouter fetch: ${url}`);
    }) as typeof fetch;
    try {
      const result = await exchangeOpenRouterCode("synthetic-code", "synthetic-verifier", controller.signal);
      expect(result).toEqual({ apiKey: "synthetic-fetched-openrouter-key", label: "synthetic-openrouter-label" });
      expect(calls).toHaveLength(2);
      expect(calls[0]).toMatchObject({
        url: "https://openrouter.ai/api/v1/auth/keys",
        method: "POST",
        signal: controller.signal,
      });
      expect(calls[0]?.headers.get("Content-Type")).toBe("application/json");
      expect(JSON.parse(calls[0]!.body)).toEqual({
        code: "synthetic-code",
        code_verifier: "synthetic-verifier",
        code_challenge_method: "S256",
      });
      expect(calls[1]).toMatchObject({
        url: "https://openrouter.ai/api/v1/auth/key",
        method: "GET",
        signal: controller.signal,
      });
      expect(calls[1]?.headers.get("Authorization")).toBe("Bearer synthetic-fetched-openrouter-key");
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});

import { request as httpRequest, type ClientRequest } from "node:http";
import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { PollerEngine } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { FetchContext, ProviderAdapter } from "../src/core/providers/adapter";
import type { UsageReport } from "../src/types";
import { createServer, type AppInstance } from "../src/server/app";

const copilotAdapter: ProviderAdapter = {
  id: "github-copilot",
  supports: provider => provider === "github-copilot",
  async fetchUsage(credential): Promise<UsageReport> {
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

async function register(app: AppInstance, email: string): Promise<string> {
  const response = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "Password12345678!" }),
  });
  if (response.status !== 201) throw new Error("Synthetic OAuth test user registration failed");
  return response.headers.get("Set-Cookie")!.split(";")[0]!;
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("device OAuth session routes", () => {
  it("rejects unknown, foreign, concurrent, and replayed device bindings before unauthorized provider polls", async () => {
    const originalFetch = globalThis.fetch;
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    registry.register(copilotAdapter);
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);
    let tokenPollCalls = 0;
    let userInfoCalls = 0;
    let tokenPollMode: "pending-gate" | "pending" | "complete" = "pending-gate";
    let gateNextPoll = false;
    const pendingPoll = Promise.withResolvers<Response>();
    const pollStarted = Promise.withResolvers<void>();

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://github.com/login/device/code") {
        return jsonResponse({
          device_code: "synthetic-copilot-device-code",
          user_code: "SYNTHETIC-CODE",
          verification_uri: "https://github.com/login/device",
          interval: 5,
          expires_in: 600,
        });
      }
      if (url === "https://github.com/login/oauth/access_token") {
        tokenPollCalls++;
        if (tokenPollMode === "pending-gate" && gateNextPoll) {
          gateNextPoll = false;
          pollStarted.resolve();
          return pendingPoll.promise;
        }
        if (tokenPollMode === "pending-gate" || tokenPollMode === "pending") {
          return jsonResponse({ error: "authorization_pending" });
        }
        return jsonResponse({ access_token: "synthetic-copilot-access-token" });
      }
      if (url === "https://api.github.com/user") {
        userInfoCalls++;
        return jsonResponse({ login: "synthetic-user", email: "synthetic@example.test" });
      }
      throw new Error(`Unexpected synthetic OAuth URL: ${url}`);
    }) as typeof fetch;

    let firstPoll: Promise<Response> | undefined;
    let ownerCookie = "";
    let sessionId = "";
    try {
      ownerCookie = await register(app, "device-oauth-owner@example.test");
      const foreignCookie = await register(app, "device-oauth-foreign@example.test");
      const unknownRequests: Array<[string, unknown]> = [
        ["/api/oauth/codex/poll", { deviceAuthId: "unknown-codex", userCode: "synthetic" }],
        ["/api/oauth/copilot/poll", { deviceCode: "unknown-copilot" }],
        ["/api/oauth/cursor/poll", { uuid: "unknown-cursor", verifier: "synthetic" }],
        ["/api/oauth/xai/poll", { deviceCode: "unknown-xai" }],
        ["/api/oauth/kimi/poll", { deviceCode: "unknown-kimi", deviceId: "synthetic" }],
      ];
      for (const [path, body] of unknownRequests) {
        const response = await app.request(path, {
          method: "POST",
          headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        expect(response.status).toBe(404);
      }
      expect(tokenPollCalls).toBe(0);

      const initiation = await app.request("/api/oauth/copilot/initiate", {
        method: "POST",
        headers: { Cookie: ownerCookie },
      });
      expect(initiation.status).toBe(200);
      const initBody = await initiation.json() as {
        success: boolean;
        data: { deviceCode: string; sessionId: string; expiresIn: number };
      };
      expect(initBody.data.sessionId).toBeTruthy();
      sessionId = initBody.data.sessionId;
      expect(initBody.data.expiresIn).toBeLessThanOrEqual(600);

      const foreignPoll = await app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: foreignCookie, "Content-Type": "application/json" },
        body: JSON.stringify({ deviceCode: initBody.data.deviceCode }),
      });
      expect(foreignPoll.status).toBe(404);
      expect(tokenPollCalls).toBe(0);

      const pollBody = JSON.stringify({ deviceCode: initBody.data.deviceCode });
      gateNextPoll = true;
      firstPoll = Promise.resolve(app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: pollBody,
      }));
      await pollStarted.promise;
      const concurrentPoll = await app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: pollBody,
      });
      expect(concurrentPoll.status).toBe(200);
      expect(await concurrentPoll.json()).toMatchObject({ status: "pending" });
      expect(tokenPollCalls).toBe(1);

      pendingPoll.resolve(jsonResponse({ error: "authorization_pending" }));
      tokenPollMode = "pending";
      expect((await firstPoll!).status).toBe(200);
      expect(await (await app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: pollBody,
      })).json()).toMatchObject({ status: "pending" });
      expect(tokenPollCalls).toBe(2);

      tokenPollMode = "complete";
      const complete = await app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: pollBody,
      });
      expect(complete.status).toBe(200);
      expect(await complete.json()).toMatchObject({ status: "complete" });
      expect(userInfoCalls).toBe(1);
      expect(tokenPollCalls).toBe(3);

      const replay = await app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: pollBody,
      });
      expect(replay.status).toBe(404);
      expect(tokenPollCalls).toBe(3);
      await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: ownerCookie },
      });
    } finally {
      pendingPoll.resolve(jsonResponse({ error: "authorization_pending" }));
      await firstPoll?.catch(() => {});
      if (sessionId && ownerCookie) {
        await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
          method: "DELETE",
          headers: { Cookie: ownerCookie },
        });
      }
      globalThis.fetch = originalFetch;
      vault.close();
    }
  });

  it("aborts an outstanding device token poll when its owner cancels", async () => {
    const originalFetch = globalThis.fetch;
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const app = createServer(vault, new PollerEngine(vault, registry), registry);
    const pollResponse = Promise.withResolvers<Response>();
    const pollStarted = Promise.withResolvers<void>();
    let pollSignal: AbortSignal | undefined;
    let tokenPollCalls = 0;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://github.com/login/device/code") {
        return jsonResponse({
          device_code: "synthetic-cancel-device",
          user_code: "CANCEL-CODE",
          verification_uri: "https://github.com/login/device",
          interval: 5,
          expires_in: 600,
        });
      }
      if (url === "https://github.com/login/oauth/access_token") {
        tokenPollCalls++;
        pollSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        pollSignal?.addEventListener("abort", () => pollResponse.reject(new Error("Synthetic device poll aborted")), { once: true });
        pollStarted.resolve();
        return pollResponse.promise;
      }
      throw new Error(`Unexpected synthetic OAuth URL: ${url}`);
    }) as typeof fetch;

    let ownerCookie = "";
    let sessionId = "";
    let pendingPoll: Promise<Response> | undefined;
    try {
      ownerCookie = await register(app, "device-oauth-cancel-owner@example.test");
      const initiation = await app.request("/api/oauth/copilot/initiate", {
        method: "POST",
        headers: { Cookie: ownerCookie },
      });
      const initBody = await initiation.json() as { data: { deviceCode: string; sessionId: string } };
      sessionId = initBody.data.sessionId;
      pendingPoll = Promise.resolve(app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: JSON.stringify({ deviceCode: initBody.data.deviceCode }),
      }));
      await pollStarted.promise;

      const canceled = await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: ownerCookie },
      });
      expect(canceled.status).toBe(200);
      expect(pollSignal?.aborted).toBe(true);
      expect((await pendingPoll!).status).toBe(404);
      expect(tokenPollCalls).toBe(1);
    } finally {
      pollResponse.reject(new Error("Synthetic device poll test cleanup"));
      await pendingPoll?.catch(() => {});
      if (ownerCookie && sessionId) {
        await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
          method: "DELETE",
          headers: { Cookie: ownerCookie },
        });
      }
      globalThis.fetch = originalFetch;
      vault.close();
    }
  });

  it("aborts staged provider validation before credential persistence on cancellation", async () => {
    const originalFetch = globalThis.fetch;
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const usageResult = Promise.withResolvers<UsageReport>();
    const validationStarted = Promise.withResolvers<void>();
    let validationSignal: AbortSignal | undefined;
    let ownerId = "";
    registry.register({
      id: "github-copilot",
      supports: provider => provider === "github-copilot",
      async fetchUsage(_credential, context?: FetchContext): Promise<UsageReport> {
        validationSignal = context?.signal;
        validationStarted.resolve();
        return usageResult.promise;
      },
    });
    const app = createServer(vault, new PollerEngine(vault, registry), registry);
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://github.com/login/device/code") {
        return jsonResponse({
          device_code: "synthetic-validation-cancel-device",
          user_code: "VALIDATE-CANCEL-CODE",
          verification_uri: "https://github.com/login/device",
          interval: 5,
          expires_in: 600,
        });
      }
      if (url === "https://github.com/login/oauth/access_token") {
        return jsonResponse({ access_token: "synthetic-copilot-candidate" });
      }
      if (url === "https://api.github.com/user") {
        return jsonResponse({ login: "synthetic-cancelled-user", email: "cancelled@example.test" });
      }
      throw new Error(`Unexpected synthetic OAuth URL: ${url}`);
    }) as typeof fetch;

    let ownerCookie = "";
    let sessionId = "";
    let pendingPoll: Promise<Response> | undefined;
    let validationResolved = false;
    try {
      const registration = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "device-oauth-validation-owner@example.test",
          password: "Password12345678!",
        }),
      });
      expect(registration.status).toBe(201);
      ownerCookie = registration.headers.get("Set-Cookie")!.split(";")[0]!;
      ownerId = (await registration.json() as { user: { id: string } }).user.id;
      const initiation = await app.request("/api/oauth/copilot/initiate", {
        method: "POST",
        headers: { Cookie: ownerCookie },
      });
      const initBody = await initiation.json() as { data: { deviceCode: string; sessionId: string } };
      sessionId = initBody.data.sessionId;
      pendingPoll = Promise.resolve(app.request("/api/oauth/copilot/poll", {
        method: "POST",
        headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
        body: JSON.stringify({ deviceCode: initBody.data.deviceCode }),
      }));
      await validationStarted.promise;

      const canceled = await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
        headers: { Cookie: ownerCookie },
      });
      expect(canceled.status).toBe(200);
      expect(validationSignal?.aborted).toBe(true);
      usageResult.resolve({
        ownerId,
        provider: "github-copilot",
        accountLabel: "cancelled@example.test",
        fetchedAt: Date.now(),
        limits: [],
        health: "healthy",
        stale: false,
        source: "live",
      });
      validationResolved = true;
      expect((await pendingPoll!).status).toBe(404);
      expect(vault.listCredentials(ownerId, "github-copilot")).toHaveLength(0);
    } finally {
      if (!validationResolved) {
        if (ownerCookie && sessionId) {
          await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
            method: "DELETE",
            headers: { Cookie: ownerCookie },
          });
        }
        usageResult.resolve({
          ownerId,
          provider: "github-copilot",
          accountLabel: "cancelled@example.test",
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          stale: false,
          source: "live",
        });
        await pendingPoll?.catch(() => {});
      }
      globalThis.fetch = originalFetch;
      vault.close();
    }
  });

  it("aborts and releases an initiation reservation when the HTTP client disconnects before receiving its session id", async () => {
    const originalFetch = globalThis.fetch;
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const app = createServer(vault, new PollerEngine(vault, registry), registry);
    const pendingProviderResponse = Promise.withResolvers<Response>();
    void pendingProviderResponse.promise.catch(() => {});
    const pendingProviderStarted = Promise.withResolvers<void>();
    const serverRequestAborted = Promise.withResolvers<void>();
    const initiationHandlerFinished = Promise.withResolvers<void>();
    const clientRequestOutcome = Promise.withResolvers<"response" | "error">();
    const clientRequestError = Promise.withResolvers<Error>();
    const clientRequestClosed = Promise.withResolvers<void>();
    const clientSocketClosed = Promise.withResolvers<void>();
    const sessionIds: string[] = [];
    let ownerId = "";
    let ownerCookie = "";
    let providerInitiations = 0;
    let providerAbortEvents = 0;
    let providerResponseSettled = false;
    let blockNextInitiation = false;
    let providerSignal: AbortSignal | undefined;
    let serverRequestSignalAborted = false;
    let serverInitiationStarted = false;
    let clientResponseReceived = false;
    let clientRequest: ClientRequest | undefined;

    const rejectPendingProviderResponse = (message: string) => {
      if (providerResponseSettled) return;
      providerResponseSettled = true;
      pendingProviderResponse.reject(new Error(message));
    };

    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: request => {
        if (
          request.method !== "POST"
          || new URL(request.url).pathname !== "/api/oauth/codex/initiate"
        ) {
          return app.fetch(request);
        }
        serverInitiationStarted = true;
        request.signal.addEventListener("abort", () => {
          serverRequestSignalAborted = true;
          serverRequestAborted.resolve();
        }, { once: true });
        return Promise.resolve(app.fetch(request)).finally(() => initiationHandlerFinished.resolve());
      },
    });
    const port = server.port;
    if (port === undefined) {
      server.stop(true);
      vault.close();
      throw new Error("Synthetic loopback server did not receive an ephemeral port");
    }

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://auth.openai.com/api/accounts/deviceauth/usercode") {
        providerInitiations++;
        if (blockNextInitiation) {
          blockNextInitiation = false;
          providerSignal = init?.signal ?? undefined;
          const rejectProviderRequest = () => {
            providerAbortEvents++;
            rejectPendingProviderResponse("Synthetic provider request aborted");
          };
          if (providerSignal?.aborted) rejectProviderRequest();
          else providerSignal?.addEventListener("abort", rejectProviderRequest, { once: true });
          pendingProviderStarted.resolve();
          return pendingProviderResponse.promise;
        }
        return jsonResponse({
          device_auth_id: `synthetic-codex-device-${providerInitiations}`,
          user_code: `SYNTHETIC-CODE-${providerInitiations}`,
          interval: 5,
          expires_in: 900,
        });
      }
      throw new Error(`Unexpected synthetic OAuth URL: ${url}`);
    }) as typeof fetch;

    try {
      const registration = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "device-oauth-http-abort@example.test",
          password: "Password12345678!",
        }),
      });
      expect(registration.status).toBe(201);
      const registrationBody = await registration.json() as { user: { id: string } };
      ownerId = registrationBody.user.id;
      ownerCookie = registration.headers.get("Set-Cookie")!.split(";")[0]!;
      for (let index = 0; index < 4; index++) {
        const response = await app.request("/api/oauth/codex/initiate", {
          method: "POST",
          headers: { Cookie: ownerCookie },
        });
        expect(response.status).toBe(200);
        const body = await response.json() as { data: { sessionId: string } };
        sessionIds.push(body.data.sessionId);
      }

      blockNextInitiation = true;
      const abortedRequest = httpRequest({
        hostname: "127.0.0.1",
        port,
        path: "/api/oauth/codex/initiate",
        method: "POST",
        headers: { Cookie: ownerCookie },
        agent: false,
      });
      clientRequest = abortedRequest;
      abortedRequest.once("response", response => {
        clientResponseReceived = true;
        response.resume();
        clientRequestOutcome.resolve("response");
      });
      abortedRequest.once("error", error => {
        clientRequestError.resolve(error);
        clientRequestOutcome.resolve("error");
      });
      abortedRequest.once("close", () => clientRequestClosed.resolve());
      abortedRequest.once("socket", socket => {
        socket.once("close", () => clientSocketClosed.resolve());
      });
      abortedRequest.end();

      await pendingProviderStarted.promise;
      abortedRequest.destroy();
      expect(await clientRequestOutcome.promise).toBe("error");
      await Promise.all([
        clientRequestError.promise,
        clientRequestClosed.promise,
        clientSocketClosed.promise,
        serverRequestAborted.promise,
      ]);
      expect(serverRequestSignalAborted).toBe(true);
      expect(providerSignal?.aborted).toBe(true);
      expect(providerAbortEvents).toBe(1);
      expect(clientResponseReceived).toBe(false);
      await initiationHandlerFinished.promise;

      const retry = await app.request("/api/oauth/codex/initiate", {
        method: "POST",
        headers: { Cookie: ownerCookie },
      });
      expect(retry.status).toBe(200);
      const retryBody = await retry.json() as { data: { sessionId: string } };
      sessionIds.push(retryBody.data.sessionId);
      expect(providerInitiations).toBe(6);
      expect(vault.listCredentials(ownerId)).toHaveLength(0);
    } finally {
      clientRequest?.destroy();
      rejectPendingProviderResponse("Synthetic provider request test cleanup");
      try {
        if (clientRequest) {
          await Promise.all([
            clientRequestOutcome.promise,
            clientRequestClosed.promise,
            clientSocketClosed.promise,
          ]);
        }
        if (serverInitiationStarted) await initiationHandlerFinished.promise;
        if (ownerCookie) {
          for (const sessionId of sessionIds) {
            await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
              method: "DELETE",
              headers: { Cookie: ownerCookie },
            });
          }
        }
      } finally {
        globalThis.fetch = originalFetch;
        server.stop(true);
        vault.close();
      }
    }
  });

  it("reserves capacity before asynchronous provider initiation and releases aborted reservations", async () => {
    const originalFetch = globalThis.fetch;
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    const app = createServer(vault, new PollerEngine(vault, registry), registry);
    const providerStarted = Promise.withResolvers<void>();
    const providerCleanup: Array<() => void> = [];
    const requestControllers: AbortController[] = [];
    const pendingInitiations: Promise<Response>[] = [];
    let providerCalls = 0;
    let providerAbortEvents = 0;
    let missingProviderSignal = false;
    let ownerCookie = "";
    let recoverySessionId = "";

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url !== "https://github.com/login/device/code") {
        throw new Error(`Unexpected synthetic OAuth URL: ${url}`);
      }
      providerCalls++;
      if (providerCalls <= 5) {
        const pending = Promise.withResolvers<Response>();
        const signal = init?.signal;
        if (!signal) missingProviderSignal = true;
        let settled = false;
        const settle = (wasAborted: boolean) => {
          if (settled) return;
          settled = true;
          if (wasAborted) providerAbortEvents++;
          pending.reject(new Error("Synthetic device initiation aborted"));
        };
        if (signal?.aborted) settle(true);
        else signal?.addEventListener("abort", () => settle(true), { once: true });
        providerCleanup.push(() => settle(false));
        if (providerCalls === 5) providerStarted.resolve();
        return pending.promise;
      }
      return jsonResponse({
        device_code: `synthetic-capacity-device-${providerCalls}`,
        user_code: `CAPACITY-${providerCalls}`,
        verification_uri: "https://github.com/login/device",
        interval: 5,
        expires_in: 600,
      });
    }) as typeof fetch;

    try {
      ownerCookie = await register(app, "device-oauth-initiation-capacity@example.test");
      for (let index = 0; index < 5; index++) {
        const controller = new AbortController();
        requestControllers.push(controller);
        pendingInitiations.push(Promise.resolve(app.request("/api/oauth/copilot/initiate", {
          method: "POST",
          headers: { Cookie: ownerCookie },
          signal: controller.signal,
        })));
      }
      await providerStarted.promise;

      const sixth = await app.request("/api/oauth/copilot/initiate", {
        method: "POST",
        headers: { Cookie: ownerCookie },
      });
      expect(sixth.status).toBe(429);
      expect(sixth.headers.get("Retry-After")).toBe("60");
      expect(await sixth.json()).toMatchObject({ errorCode: "OAUTH_CAPACITY" });
      expect(providerCalls).toBe(5);

      for (const controller of requestControllers) controller.abort();
      expect(missingProviderSignal).toBe(false);
      await Promise.all(pendingInitiations);
      expect(providerAbortEvents).toBe(5);

      const recovered = await app.request("/api/oauth/copilot/initiate", {
        method: "POST",
        headers: { Cookie: ownerCookie },
      });
      expect(recovered.status).toBe(200);
      const recoveredBody: unknown = await recovered.json();
      if (
        !recoveredBody ||
        typeof recoveredBody !== "object" ||
        !("data" in recoveredBody) ||
        !recoveredBody.data ||
        typeof recoveredBody.data !== "object" ||
        !("sessionId" in recoveredBody.data) ||
        typeof recoveredBody.data.sessionId !== "string"
      ) {
        throw new Error("Synthetic device initiate response omitted its session id");
      }
      recoverySessionId = recoveredBody.data.sessionId;
      expect(providerCalls).toBe(6);
    } finally {
      for (const controller of requestControllers) controller.abort();
      for (const cleanup of providerCleanup) cleanup();
      await Promise.all(pendingInitiations.map(pending => pending.catch(() => new Response())));
      if (ownerCookie && recoverySessionId) {
        await app.request(`/api/oauth/sessions/${encodeURIComponent(recoverySessionId)}`, {
          method: "DELETE",
          headers: { Cookie: ownerCookie },
        });
      }
      globalThis.fetch = originalFetch;
      vault.close();
    }
  });

  it("persists provider-discovered Cursor identities instead of overwriting a generic account", async () => {
    const originalFetch = globalThis.fetch;
    const vault = new StorageVault(":memory:");
    const registry = new ProviderRegistry();
    registry.register({
      id: "cursor",
      supports: provider => provider === "cursor",
      async fetchUsage(credential): Promise<UsageReport> {
        const accountLabel = credential.secret === "synthetic-cursor-account-a-token"
          ? "cursor-account-a"
          : "cursor-account-b";
        return {
          ownerId: credential.ownerId,
          provider: "cursor",
          accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          stale: false,
          source: "live",
        };
      },
    });
    const app = createServer(vault, new PollerEngine(vault, registry), registry);
    let pollCalls = 0;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.startsWith("https://api2.cursor.sh/auth/poll?")) {
        pollCalls++;
        return jsonResponse({
          accessToken: pollCalls === 1
            ? "synthetic-cursor-account-a-token"
            : "synthetic-cursor-account-b-token",
          refreshToken: `synthetic-cursor-refresh-${pollCalls}`,
        });
      }
      throw new Error(`Unexpected synthetic Cursor OAuth URL: ${url}`);
    }) as typeof fetch;

    let ownerCookie = "";
    let ownerId = "";
    const sessionIds: string[] = [];
    try {
      const registration = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "cursor-discovered-identities@example.test",
          password: "Password12345678!",
        }),
      });
      expect(registration.status).toBe(201);
      ownerCookie = registration.headers.get("Set-Cookie")!.split(";")[0]!;
      ownerId = (await registration.json() as { user: { id: string } }).user.id;
      for (const expectedLabel of ["cursor-account-a", "cursor-account-b"]) {
        const initiation = await app.request("/api/oauth/cursor/initiate", {
          method: "POST",
          headers: { Cookie: ownerCookie },
        });
        expect(initiation.status).toBe(200);
        const initBody = await initiation.json() as {
          data: { uuid: string; verifier: string; sessionId: string };
        };
        sessionIds.push(initBody.data.sessionId);

        const poll = await app.request("/api/oauth/cursor/poll", {
          method: "POST",
          headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
          body: JSON.stringify({ uuid: initBody.data.uuid, verifier: initBody.data.verifier }),
        });
        expect(poll.status).toBe(200);
        expect(await poll.json()).toMatchObject({ status: "complete", data: { accountLabel: expectedLabel } });
      }

      const credentials = vault.listCredentials(ownerId, "cursor");
      expect(credentials.map(credential => credential.accountLabel).sort()).toEqual([
        "cursor-account-a",
        "cursor-account-b",
      ]);
      expect(new Set(credentials.map(credential => credential.id)).size).toBe(2);
      expect(credentials.some(credential => credential.accountLabel === "Cursor")).toBe(false);
      expect(pollCalls).toBe(2);
    } finally {
      if (ownerCookie) {
        for (const sessionId of sessionIds) {
          await app.request(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
            method: "DELETE",
            headers: { Cookie: ownerCookie },
          });
        }
      }
      globalThis.fetch = originalFetch;
      vault.close();
    }
  });
});

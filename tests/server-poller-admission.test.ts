import { describe, expect, it } from "bun:test";
import { PollerEngine, type PollerOptions } from "../src/core/poller/poller";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { FetchContext, ProviderAdapter } from "../src/core/providers/adapter";
import { StorageVault } from "../src/core/storage/vault";
import { createServer, type AppInstance, type ServerOptions } from "../src/server/app";
import type { StoredCredential, UsageReport } from "../src/types";

interface AdapterCall {
  ownerId: string;
  provider: string;
  secret: string;
}

interface AdapterTracker {
  calls: AdapterCall[];
  activeCalls: number;
  peakActiveCalls: number;
  beforeFetch: (credential: StoredCredential) => Promise<void>;
}

interface TestContext {
  app: AppInstance;
  poller: PollerEngine;
  tracker: AdapterTracker;
  vault: StorageVault;
}

interface TestUser {
  cookie: string;
  id: string;
}

interface CredentialSeed {
  provider: string;
  accountLabel: string;
  secret: string;
  accent?: string;
  metadata?: Record<string, unknown>;
}

interface AdmissionResponse {
  success?: boolean;
  error?: string;
  errorCode?: string;
  admissionCode?: string;
  retryAfter?: number;
  restartRequired?: boolean;
  status?: string;
}

function createTestContext(
  providers: string[],
  options: PollerOptions,
  serverOptions?: ServerOptions,
): TestContext {
  const vault = new StorageVault(":memory:");
  const registry = new ProviderRegistry();
  const tracker: AdapterTracker = {
    calls: [],
    activeCalls: 0,
    peakActiveCalls: 0,
    beforeFetch: async () => {},
  };

  for (const provider of providers) {
    const adapter: ProviderAdapter = {
      id: provider,
      supports: candidate => candidate.toLowerCase() === provider,
      async fetchUsage(credential: StoredCredential, _context?: FetchContext): Promise<UsageReport> {
        tracker.calls.push({
          ownerId: credential.ownerId ?? "",
          provider: credential.provider,
          secret: credential.secret,
        });
        tracker.activeCalls++;
        tracker.peakActiveCalls = Math.max(tracker.peakActiveCalls, tracker.activeCalls);
        try {
          await tracker.beforeFetch(credential);
          return {
            ownerId: credential.ownerId,
            provider: credential.provider,
            accountLabel: credential.accountLabel,
            fetchedAt: Date.now(),
            limits: [{
              id: "requests",
              label: "Requests",
              amount: { used: 1, limit: 10, remaining: 9, unit: "requests" },
              status: "ok",
            }],
            raw: {
              credentialSecret: credential.secret,
              privateMetadata: credential.metadata,
            },
          };
        } finally {
          tracker.activeCalls--;
        }
      },
    };
    registry.register(adapter);
  }

  const poller = new PollerEngine(vault, registry, options);
  return { app: createServer(vault, poller, registry, undefined, serverOptions), poller, tracker, vault };
}

async function registerUser(app: AppInstance, email: string): Promise<TestUser> {
  const response = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "Password12345678!" }),
  });
  expect(response.status).toBe(201);
  const cookie = response.headers.get("Set-Cookie")?.split(";")[0];
  if (!cookie) throw new Error("Registration did not return a session cookie.");
  const body = await response.json() as { user: { id: string } };
  return { cookie, id: body.user.id };
}

async function addCredential(app: AppInstance, cookie: string, seed: CredentialSeed): Promise<string> {
  const response = await app.request("/api/credentials", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ ...seed, credentialType: "api_key" }),
  });
  expect(response.status).toBe(200);
  const body = await response.json() as { data: { id: string } };
  return body.data.id;
}

describe("bounded poller HTTP admission", () => {
  it("returns safe capacity 429s for manual, credential-create, and bulk requests without treating overflow as provider failure", async () => {
    const { app, poller, tracker, vault } = createTestContext(
      ["synthetic-a", "synthetic-b", "synthetic-c", "synthetic-d"],
      {
        maxConcurrentGlobal: 1,
        maxConcurrentPerProvider: 1,
        minProviderIntervalMs: 0,
        maxQueuedJobs: 1,
        admissionTimeoutMs: 2_000,
      },
    );
    const activeStarted = Promise.withResolvers<void>();
    const releaseActive = Promise.withResolvers<void>();
    let activePoll: Promise<UsageReport | null> | undefined;
    let queuedPoll: Promise<UsageReport | null> | undefined;
    const httpRequests: Promise<Response>[] = [];

    try {
      const owner = await registerUser(app, "admission-owner@example.com");
      const credentialA = await addCredential(app, owner.cookie, {
        provider: "synthetic-a",
        accountLabel: "A account",
        secret: "seed-a-secret",
        metadata: { email: "a@example.com", refreshToken: "a-private-refresh" },
      });
      const credentialB = await addCredential(app, owner.cookie, {
        provider: "synthetic-b",
        accountLabel: "B account",
        secret: "seed-b-secret",
      });
      const credentialC = await addCredential(app, owner.cookie, {
        provider: "synthetic-c",
        accountLabel: "C account",
        secret: "seed-c-secret",
        accent: "violet",
        metadata: { email: "c@example.com", refreshToken: "c-private-refresh", privateMarker: "not-public" },
      });
      const cachedBefore = vault.getLatestUsage(owner.id).find(report => report.credentialId === credentialC);
      const snapshotsBefore = vault.getSnapshotHistory(owner.id, "synthetic-c");
      const credentialBefore = vault.getCredential(owner.id, credentialC);
      const cCallsBefore = tracker.calls.filter(call => call.secret === "seed-c-secret").length;

      tracker.beforeFetch = async credential => {
        if (credential.secret === "seed-a-secret") {
          activeStarted.resolve();
          await releaseActive.promise;
        }
      };
      activePoll = poller.pollCredential(owner.id, credentialA);
      await activeStarted.promise;
      queuedPoll = poller.pollCredential(owner.id, credentialB);

      const saturatedPoll = Promise.resolve(app.request(`/api/credentials/${credentialC}/poll`, {
        method: "POST",
        headers: { Cookie: owner.cookie },
      }));
      httpRequests.push(saturatedPoll);
      const pollResponse = await saturatedPoll;
      expect(pollResponse.status).toBe(429);
      expect(pollResponse.headers.get("Retry-After")).toBe("30");
      const pollBody = await pollResponse.json() as AdmissionResponse;
      expect(pollBody).toMatchObject({
        success: false,
        errorCode: "POLLER_CAPACITY",
        admissionCode: "QUEUE_FULL",
        retryAfter: 30,
      });
      expect(pollBody.error).toContain("Rate limit exceeded");

      const createOverflow = Promise.resolve(app.request("/api/credentials", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: owner.cookie },
        body: JSON.stringify({
          provider: "synthetic-d",
          accountLabel: "D account",
          credentialType: "api_key",
          secret: "overflow-d-secret",
          metadata: { refreshToken: "overflow-private-refresh" },
        }),
      }));
      httpRequests.push(createOverflow);
      const createResponse = await createOverflow;
      expect(createResponse.status).toBe(429);
      expect(createResponse.headers.get("Retry-After")).toBe("30");
      const createBody = await createResponse.json() as AdmissionResponse;
      expect(createBody).toMatchObject({ errorCode: "POLLER_CAPACITY", admissionCode: "QUEUE_FULL" });
      expect(createBody.error).toContain("Rate limit exceeded");
      expect(JSON.stringify(createBody)).not.toContain("overflow-d-secret");
      expect(JSON.stringify(createBody)).not.toContain("overflow-private-refresh");
      expect(vault.listCredentials(owner.id).some(credential => credential.provider === "synthetic-d")).toBe(false);
      expect(tracker.calls.some(call => call.secret === "overflow-d-secret")).toBe(false);

      const bulkPoll = Promise.resolve(app.request("/api/poll", {
        method: "POST",
        headers: { Cookie: owner.cookie },
      }));
      httpRequests.push(bulkPoll);

      expect(vault.getSnapshotHistory(owner.id, "synthetic-c")).toEqual(snapshotsBefore);
      expect(vault.getLatestUsage(owner.id).find(report => report.credentialId === credentialC)).toEqual(cachedBefore);
      expect(vault.getCredential(owner.id, credentialC)).toEqual(credentialBefore);
      expect(tracker.calls.filter(call => call.secret === "seed-c-secret")).toHaveLength(cCallsBefore);

      releaseActive.resolve();
      const [activeReport, queuedReport, bulkResponse] = await Promise.all([
        activePoll,
        queuedPoll,
        bulkPoll,
      ]);
      expect(activeReport).not.toBeNull();
      expect(queuedReport).not.toBeNull();
      expect(bulkResponse.status).toBe(429);
      expect(bulkResponse.headers.get("Retry-After")).toBe("30");
      const bulkBody = await bulkResponse.json() as AdmissionResponse;
      expect(bulkBody).toMatchObject({
        errorCode: "POLLER_CAPACITY",
        admissionCode: "QUEUE_FULL",
        retryAfter: 30,
      });
      expect(bulkBody.error).toContain("Rate limit exceeded");
      expect(vault.getSnapshotHistory(owner.id, "synthetic-c")).toEqual(snapshotsBefore);
      expect(tracker.calls.filter(call => call.secret === "seed-c-secret")).toHaveLength(cCallsBefore);
    } finally {
      releaseActive.resolve();
      const pending: Promise<unknown>[] = [...httpRequests];
      if (activePoll) pending.push(activePoll);
      if (queuedPoll) pending.push(queuedPoll);
      await Promise.allSettled(pending);
      poller.stop();
      vault.close();
    }
  });

  it("returns admission-timeout 429 while preserving the queued credential's cached state and avoiding its SDK call", async () => {
    const { app, poller, tracker, vault } = createTestContext(
      ["synthetic-a", "synthetic-b"],
      {
        maxConcurrentGlobal: 1,
        maxConcurrentPerProvider: 1,
        minProviderIntervalMs: 0,
        maxQueuedJobs: 1,
        admissionTimeoutMs: 30,
      },
    );
    const activeStarted = Promise.withResolvers<void>();
    const releaseActive = Promise.withResolvers<void>();
    let activePoll: Promise<UsageReport | null> | undefined;
    let queuedPoll: Promise<Response> | undefined;

    try {
      const owner = await registerUser(app, "admission-timeout@example.com");
      const credentialA = await addCredential(app, owner.cookie, {
        provider: "synthetic-a",
        accountLabel: "A account",
        secret: "timeout-active-secret",
      });
      const credentialB = await addCredential(app, owner.cookie, {
        provider: "synthetic-b",
        accountLabel: "B account",
        secret: "timeout-queued-secret",
        metadata: { email: "b@example.com", refreshToken: "b-private-refresh" },
      });
      const cachedBefore = vault.getLatestUsage(owner.id).find(report => report.credentialId === credentialB);
      const snapshotsBefore = vault.getSnapshotHistory(owner.id, "synthetic-b");
      const credentialBefore = vault.getCredential(owner.id, credentialB);
      const bCallsBefore = tracker.calls.filter(call => call.secret === "timeout-queued-secret").length;

      tracker.beforeFetch = async credential => {
        if (credential.secret === "timeout-active-secret") {
          activeStarted.resolve();
          await releaseActive.promise;
        }
      };
      activePoll = poller.pollCredential(owner.id, credentialA);
      await activeStarted.promise;
      queuedPoll = Promise.resolve(app.request(`/api/credentials/${credentialB}/poll`, {
        method: "POST",
        headers: { Cookie: owner.cookie },
      }));
      // This deliberately uses the pool's real short monotonic deadline; fake timers do not advance its performance.now() admission clock.
      const timeoutResponse = await queuedPoll;
      expect(timeoutResponse.status).toBe(429);
      expect(timeoutResponse.headers.get("Retry-After")).toBe("30");
      const timeoutBody = await timeoutResponse.json() as AdmissionResponse;
      expect(timeoutBody).toMatchObject({
        success: false,
        errorCode: "POLLER_CAPACITY",
        admissionCode: "ADMISSION_TIMEOUT",
        retryAfter: 30,
      });
      expect(timeoutBody.error).toContain("Rate limit exceeded");
      expect(vault.getSnapshotHistory(owner.id, "synthetic-b")).toEqual(snapshotsBefore);
      expect(vault.getLatestUsage(owner.id).find(report => report.credentialId === credentialB)).toEqual(cachedBefore);
      expect(vault.getCredential(owner.id, credentialB)).toEqual(credentialBefore);
      expect(tracker.calls.filter(call => call.secret === "timeout-queued-secret")).toHaveLength(bCallsBefore);

      releaseActive.resolve();
      expect(await activePoll).not.toBeNull();
    } finally {
      releaseActive.resolve();
      const pending: Promise<unknown>[] = [];
      if (activePoll) pending.push(activePoll);
      if (queuedPoll) pending.push(queuedPoll);
      await Promise.allSettled(pending);
      poller.stop();
      vault.close();
    }
  });

  it("runs the authenticated bulk API across providers in parallel and returns only owner-bound public projections", async () => {
    const { app, poller, tracker, vault } = createTestContext(
      ["synthetic-a", "synthetic-b", "synthetic-c"],
      {
        maxConcurrentGlobal: 2,
        maxConcurrentPerProvider: 1,
        minProviderIntervalMs: 0,
        maxQueuedJobs: 8,
        admissionTimeoutMs: 1_000,
      },
    );
    let blockedOwnerId = "";
    let bulkRequest: Promise<Response> | undefined;

    try {
      const owner = await registerUser(app, "bulk-owner@example.com");
      const otherOwner = await registerUser(app, "bulk-other@example.com");
      const credentialA = await addCredential(app, owner.cookie, {
        provider: "synthetic-a",
        accountLabel: "Owner A",
        secret: "bulk-owner-a-secret",
        accent: "cyan",
        metadata: {
          email: "owner-a@example.com",
          login: "owner-a-login",
          planType: "pro",
          refreshToken: "owner-a-private-refresh",
          privateMarker: "owner-a-private-marker",
        },
      });
      const credentialB = await addCredential(app, owner.cookie, {
        provider: "synthetic-b",
        accountLabel: "Owner B",
        secret: "bulk-owner-b-secret",
        accent: "violet",
        metadata: {
          email: "owner-b@example.com",
          login: "owner-b-login",
          planType: "team",
          refreshToken: "owner-b-private-refresh",
          privateMarker: "owner-b-private-marker",
        },
      });
      const foreignCredential = await addCredential(app, otherOwner.cookie, {
        provider: "synthetic-c",
        accountLabel: "Other Tenant Account",
        secret: "foreign-tenant-secret",
        metadata: { email: "other@example.com", refreshToken: "foreign-private-refresh" },
      });
      const foreignCallsBefore = tracker.calls.filter(call => call.ownerId === otherOwner.id).length;
      blockedOwnerId = owner.id;
      tracker.beforeFetch = async credential => {
        if (credential.ownerId === blockedOwnerId) await Promise.resolve();
      };

      const request = Promise.resolve(app.request("/api/poll", {
        method: "POST",
        headers: { Cookie: owner.cookie },
      }));
      bulkRequest = request;
      const response = await request;
      expect(tracker.peakActiveCalls).toBeGreaterThanOrEqual(2);
      expect(response.status).toBe(200);
      const body = await response.json() as {
        success: boolean;
        count: number;
        data: Array<Record<string, unknown>>;
      };
      expect(body.success).toBe(true);
      expect(body.count).toBe(2);
      expect(body.data.map(report => report["credentialId"])).toEqual(
        expect.arrayContaining([credentialA, credentialB]),
      );
      expect(body.data.some(report => report["credentialId"] === foreignCredential)).toBe(false);
      expect(body.data.some(report => report["accountLabel"] === "Other Tenant Account")).toBe(false);
      const reportA = body.data.find(report => report["credentialId"] === credentialA);
      const reportB = body.data.find(report => report["credentialId"] === credentialB);
      expect(reportA).toMatchObject({
        accountLabel: "Owner A",
        accent: "cyan",
        createdAt: vault.getCredential(owner.id, credentialA)?.createdAt,
        metadata: { email: "owner-a@example.com", login: "owner-a-login", planType: "pro" },
        limits: [{ id: "requests", amount: { unit: "requests", remaining: 9 } }],
      });
      expect(reportB).toMatchObject({
        accountLabel: "Owner B",
        accent: "violet",
        createdAt: vault.getCredential(owner.id, credentialB)?.createdAt,
        metadata: { email: "owner-b@example.com", login: "owner-b-login", planType: "team" },
      });
      expect(JSON.stringify(body)).not.toContain("owner-a-private-refresh");
      expect(JSON.stringify(body)).not.toContain("owner-b-private-refresh");
      expect(JSON.stringify(body)).not.toContain("owner-a-private-marker");
      expect(JSON.stringify(body)).not.toContain("owner-b-private-marker");
      expect(JSON.stringify(body)).not.toContain("bulk-owner-a-secret");
      expect(JSON.stringify(body)).not.toContain("bulk-owner-b-secret");
      expect(JSON.stringify(body)).not.toContain("foreign-tenant-secret");
      expect(JSON.stringify(body)).not.toContain("privateMetadata");
      expect(JSON.stringify(body)).not.toContain("raw");
      expect(JSON.stringify(body)).not.toContain("ownerId");
      expect(tracker.calls.filter(call => call.ownerId === otherOwner.id)).toHaveLength(foreignCallsBefore);
    } finally {
      if (bulkRequest) await Promise.allSettled([bulkRequest]);
      poller.stop();
      vault.close();
    }
  });
  it("localizes terminal public Google callback capacity responses and marks them restart-required", async () => {
    const environmentKeys = [
      "NODE_ENV",
      "GOOGLE_OAUTH_CLIENT_ID",
      "GOOGLE_OAUTH_CLIENT_SECRET",
      "GOOGLE_OAUTH_REDIRECT_URI",
      "CREDENTIAL_METADATA_ENCRYPTION",
      "USAGE_MASTER_KEY",
    ] as const;
    const savedEnvironment = new Map<string, string | undefined>();
    for (const key of environmentKeys) savedEnvironment.set(key, process.env[key]);
    const activeStarted = Promise.withResolvers<void>();
    const releaseActive = Promise.withResolvers<void>();
    let context: TestContext | undefined;
    let activePoll: Promise<UsageReport | null> | undefined;
    let queuedPoll: Promise<UsageReport | null> | undefined;
    let exchangeCount = 0;

    try {
      process.env["NODE_ENV"] = "production";
      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "synthetic-capacity-client.apps.googleusercontent.com";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "synthetic-capacity-client-secret";
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";
      process.env["CREDENTIAL_METADATA_ENCRYPTION"] = "";
      process.env["USAGE_MASTER_KEY"] = "synthetic-capacity-test-master-key";

      const testContext = createTestContext(
        ["synthetic-a", "synthetic-b", "antigravity"],
        {
          maxConcurrentGlobal: 1,
          maxConcurrentPerProvider: 1,
          minProviderIntervalMs: 0,
          maxQueuedJobs: 1,
          admissionTimeoutMs: 2_000,
        },
        {
          googleOAuthExchange: async () => {
            exchangeCount++;
            return {
              accessToken: `synthetic-google-access-${exchangeCount}`,
              email: `capacity-google-${exchangeCount}@example.com`,
            };
          },
        },
      );
      context = testContext;
      const owner = await registerUser(testContext.app, "google-capacity-owner@example.com");
      const credentialA = await addCredential(testContext.app, owner.cookie, {
        provider: "synthetic-a",
        accountLabel: "A account",
        secret: "google-capacity-active-secret",
      });
      const credentialB = await addCredential(testContext.app, owner.cookie, {
        provider: "synthetic-b",
        accountLabel: "B account",
        secret: "google-capacity-queued-secret",
      });

      testContext.tracker.beforeFetch = async credential => {
        if (credential.secret === "google-capacity-active-secret") {
          activeStarted.resolve();
          await releaseActive.promise;
        }
      };
      activePoll = testContext.poller.pollCredential(owner.id, credentialA);
      await activeStarted.promise;
      queuedPoll = testContext.poller.pollCredential(owner.id, credentialB);

      for (const locale of [
        {
          acceptLanguage: "tr-TR,tr;q=0.9,en-US;q=0.8",
          htmlLanguage: "tr",
          title: "Yetkilendirme Tamamlanamadı",
          message: "Sorgulama hız sınırına ulaşıldı.",
        },
        {
          acceptLanguage: "en-US,en;q=0.9,tr;q=0.8",
          htmlLanguage: "en",
          title: "Authorization Not Completed",
          message: "Rate limit exceeded. Please wait before polling again.",
        },
      ]) {
        const initiation = await Promise.resolve(testContext.app.request("/api/oauth/google/initiate", {
          method: "POST",
          headers: { Cookie: owner.cookie },
        }));
        expect(initiation.status).toBe(200);
        const initiationBody = await initiation.json() as { data?: { sessionId?: string } };
        const sessionId = initiationBody.data?.sessionId;
        if (!sessionId) throw new Error("Google initiation omitted its session ID.");

        const callbackQuery = new URLSearchParams({
          code: "synthetic-redeemed-google-code",
          state: sessionId,
        });
        const callback = await Promise.resolve(testContext.app.request(
          `/api/oauth/google/callback?${callbackQuery.toString()}`,
          { headers: { "Accept-Language": locale.acceptLanguage } },
        ));
        expect(callback.status).toBe(429);
        expect(callback.headers.get("Retry-After")).toBe("30");
        const html = await callback.text();
        expect(html).toContain(`lang="${locale.htmlLanguage}"`);
        expect(html).toContain(`data-error-code="POLLER_CAPACITY"`);
        expect(html).toContain(`data-admission-code="QUEUE_FULL"`);
        expect(html).toContain(`data-restart-required="true"`);
        expect(html).toContain(locale.title);
        expect(html).toContain(locale.message);
        expect(html).not.toContain("synthetic-redeemed-google-code");
        expect(html).not.toContain("synthetic-google-access-");

        const status = await Promise.resolve(testContext.app.request(
          `/api/oauth/status/${encodeURIComponent(sessionId)}`,
          { headers: { Cookie: owner.cookie } },
        ));
        expect(status.status).toBe(200);
        expect(await status.json()).toMatchObject({ status: "error", restartRequired: true });
      }

      expect(exchangeCount).toBe(2);
      expect(testContext.vault.listCredentials(owner.id).some(credential => credential.provider === "antigravity")).toBe(false);
      expect(testContext.tracker.calls.some(call => call.provider === "antigravity")).toBe(false);
    } finally {
      releaseActive.resolve();
      const pending: Promise<unknown>[] = [];
      if (activePoll) pending.push(activePoll);
      if (queuedPoll) pending.push(queuedPoll);
      await Promise.allSettled(pending);
      context?.poller.stop();
      context?.vault.close();
      for (const key of environmentKeys) {
        const value = savedEnvironment.get(key);
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });
});

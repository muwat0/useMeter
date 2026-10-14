import { afterEach, describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { PollerEngine } from "../src/core/poller/poller";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { createServer, type AppInstance } from "../src/server/app";
import type { FetchContext, ProviderAdapter } from "../src/core/providers/adapter";
import type { StoredCredential, UsageReport } from "../src/types";

const DEVICE_AUTHORIZATION_URL = "https://auth.kimi.com/api/oauth/device_authorization";
const TOKEN_URL = "https://auth.kimi.com/api/oauth/token";
const USAGES_URL = "https://api.kimi.com/coding/v1/usages";
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const ACCOUNT_ID = "kimi-account-4242";

function createSyntheticJwt(accountId: string = ACCOUNT_ID, deviceId: string = "synthetic-kimi-device-id"): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    user_id: accountId,
    device_id: deviceId,
    exp: 4_102_444_800,
  })).toString("base64url");
  const signature = Buffer.from("local-test-signature").toString("base64url");
  return `${header}.${payload}.${signature}`;
}

const ACCESS_TOKEN = createSyntheticJwt();
const REFRESH_TOKEN = "synthetic-kimi-refresh-token-for-tests-only";
const REPEAT_ACCESS_TOKEN = createSyntheticJwt(ACCOUNT_ID, "synthetic-kimi-device-repeat");
const REPEAT_REFRESH_TOKEN = "synthetic-kimi-repeat-refresh-token";
const OFFICIAL_USAGE_PAYLOAD = {
  goods_version: 2,
  usages: {
    limit_5h: { used_ratio: 0.3, reset_time: "2027-09-26T18:00:00Z" },
    limit_7d: { used_ratio: 0.2, reset_time: "2027-10-03T00:00:00Z" },
    limit_month_total: { used_ratio: 0.4, reset_time: "2027-10-01T00:00:00Z" },
    limit_month_code: { used_ratio: 0.25, reset_time: "2027-10-01T00:00:00Z" },
  },
  boosterWallet: {
    balance: { type: "BOOSTER", amount: "20000000000", amountLeft: "10000000000" },
    monthlyChargeLimitEnabled: true,
    monthlyChargeLimit: { currency: "CNY", priceInCents: "20000" },
    monthlyUsed: { currency: "CNY", priceInCents: "5000" },
  },
};

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (let index = cleanups.length - 1; index >= 0; index -= 1) {
    cleanups[index]?.();
  }
  cleanups.length = 0;
});

interface MockFetchCall {
  url: string;
  method: string;
}

interface KimiFetchMock {
  calls: MockFetchCall[];
  deviceCode: string;
  deviceId?: string;
  usagePayload: unknown;
  usageStatus: number;
  accessToken?: string;
  refreshToken?: string | null;
}

function installKimiFetch(usagePayload: unknown, deviceCode: string, usageStatus = 200): KimiFetchMock {
  const originalFetch = globalThis.fetch;
  const mock: KimiFetchMock = { calls: [], deviceCode, usagePayload, usageStatus };
  cleanups.push(() => {
    globalThis.fetch = originalFetch;
  });

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : undefined;
    const url = request?.url ?? String(input);
    const method = (init?.method ?? request?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers ?? request?.headers);
    const body = typeof init?.body === "string" ? init.body : "";
    mock.calls.push({ url, method });

    if (url === DEVICE_AUTHORIZATION_URL) {
      if (method !== "POST") throw new Error(`Unexpected method for Kimi device authorization: ${method}`);
      if (!new URLSearchParams(body).get("client_id")) throw new Error("Kimi device authorization omitted client_id");
      mock.deviceId = headers.get("X-Msh-Device-Id") ?? undefined;
      if (!mock.deviceId || !/^[0-9a-f]{32}$/i.test(mock.deviceId)) {
        throw new Error("Kimi device authorization used an invalid device id");
      }
      return Response.json({
        device_code: mock.deviceCode,
        user_code: "TEST-CODE",
        verification_uri: "https://www.kimi.com/code/authorize_device",
        expires_in: 900,
        interval: 5,
      });
    }

    if (url === TOKEN_URL) {
      if (method !== "POST") throw new Error(`Unexpected method for Kimi token exchange: ${method}`);
      const parameters = new URLSearchParams(body);
      if (parameters.get("device_code") !== mock.deviceCode) throw new Error("Kimi token exchange used the wrong device code");
      if (parameters.get("grant_type") !== DEVICE_CODE_GRANT) throw new Error("Kimi token exchange used the wrong grant type");
      if (!parameters.get("client_id")) throw new Error("Kimi token exchange omitted client_id");
      if (!mock.deviceId || headers.get("X-Msh-Device-Id") !== mock.deviceId) {
        throw new Error("Kimi token exchange did not reuse the authorized device id");
      }
      const tokenPayload: Record<string, unknown> = {
        access_token: mock.accessToken ?? ACCESS_TOKEN,
      };
      if (mock.refreshToken !== null) {
        tokenPayload["refresh_token"] = mock.refreshToken ?? REFRESH_TOKEN;
      }
      return Response.json(tokenPayload);
    }
    if (url === USAGES_URL) {
      if (method !== "GET") throw new Error(`Unexpected method for Kimi usages: ${method}`);
      const expectedToken = mock.accessToken ?? ACCESS_TOKEN;
      if (headers.get("Authorization") !== `Bearer ${expectedToken}`) {
        throw new Error("Kimi usages request did not use the issued access token");
      }
      if (headers.get("Accept") !== "application/json") {
        throw new Error("Kimi usages request did not set Accept: application/json");
      }
      if (headers.has("X-Msh-Device-Id") || headers.has("User-Agent")) {
        throw new Error("Kimi usages request must not include spoofed device or user-agent headers");
      }
      return Response.json(mock.usagePayload, { status: mock.usageStatus });
    }

    throw new Error(`Unexpected Kimi onboarding URL: ${method} ${url}`);
  }) as unknown as typeof fetch;

  return mock;
}

function createHarness(usagePayload: unknown, deviceCode: string, usageStatus = 200) {
  const vault = new StorageVault(":memory:");
  vault.setRegistrationAllowed(true);
  cleanups.push(() => vault.close());
  const registry = createDefaultRegistry();
  const poller = new PollerEngine(vault, registry, {
    maxConcurrentPerProvider: 2,
    minProviderIntervalMs: 0,
  });
  const app = createServer(vault, poller, registry);
  const fetchMock = installKimiFetch(usagePayload, deviceCode, usageStatus);
  return { app, vault, poller, registry, fetchMock };
}

async function registerUser(app: AppInstance, email: string) {
  const response = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "Password12345678!" }),
  });
  expect(response.status).toBe(201);
  const body = await response.json() as { user: { id: string } };
  const setCookie = response.headers.get("Set-Cookie");
  if (!setCookie) throw new Error("Registration did not issue an authenticated session cookie");
  return { userId: body.user.id, cookie: setCookie.split(";")[0]! };
}

function authenticatedJson(cookie: string, body?: unknown): RequestInit {
  return {
    method: "POST",
    headers: {
      Cookie: cookie,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

describe("Kimi device authorization onboarding integration", () => {
  it("authorizes, stores the encrypted credential, reports official quota windows, masks secrets, and isolates tenants", async () => {
    const deviceCode = "synthetic-kimi-device-success";
    const { app, vault, fetchMock } = createHarness(OFFICIAL_USAGE_PAYLOAD, deviceCode);
    const owner = await registerUser(app, "kimi-owner@example.com");
    const otherTenant = await registerUser(app, "kimi-other@example.com");

    const initiateResponse = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    expect(initiateResponse.status).toBe(200);
    const initiateBody = await initiateResponse.json() as {
      success: boolean;
      data: { deviceCode: string; deviceId: string; userCode: string; verificationUrl: string };
    };
    expect(initiateBody.success).toBe(true);
    expect(initiateBody.data).toMatchObject({
      deviceCode,
      userCode: "TEST-CODE",
      verificationUrl: "https://www.kimi.com/code/authorize_device",
    });
    expect(initiateBody.data.deviceId).toBe(fetchMock.deviceId!);

    const pollBody = { deviceCode, deviceId: initiateBody.data.deviceId };
    const otherTenantResponse = await app.request(
      "/api/oauth/kimi/poll",
      authenticatedJson(otherTenant.cookie, pollBody),
    );
    expect(otherTenantResponse.status).toBe(404);
    expect(await otherTenantResponse.json()).toMatchObject({ status: "error" });
    expect(fetchMock.calls.map(call => call.url)).toEqual([DEVICE_AUTHORIZATION_URL]);
    expect(vault.listCredentials(otherTenant.userId, "kimi-code")).toHaveLength(0);

    const pollResponse = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, pollBody));
    expect(pollResponse.status).toBe(200);
    const pollResult = await pollResponse.json() as {
      status: string;
      data?: { id: string; accountLabel: string };
    };
    expect(pollResult).toMatchObject({ status: "complete", data: { accountLabel: ACCOUNT_ID } });
    expect(pollResult.data?.id).toBeTruthy();

    const storedCredentials = vault.listCredentials(owner.userId, "kimi-code");
    expect(storedCredentials).toHaveLength(1);
    const stored = vault.getCredential(owner.userId, pollResult.data!.id);
    expect(stored).toMatchObject({
      ownerId: owner.userId,
      provider: "kimi-code",
      credentialType: "oauth",
      accountLabel: ACCOUNT_ID,
      secret: ACCESS_TOKEN,
      metadata: { refreshToken: REFRESH_TOKEN, accountId: ACCOUNT_ID },
    });

    const dataResponse = await app.request("/api/data", { headers: { Cookie: owner.cookie } });
    expect(dataResponse.status).toBe(200);
    const apiData = await dataResponse.json() as {
      success: boolean;
      data: Array<{
        provider: string;
        credentialId: string;
        accountLabel: string;
        health?: string;
        source?: string;
        limits: Array<{
          id: string;
          amount: { used: number; remaining?: number; limit: number; unit: string };
          status: string;
          notes?: string[];
          window?: { id: string; durationMs?: number; resetsAt?: number };
        }>;
      }>;
    };
    expect(apiData.success).toBe(true);
    expect(apiData.data).toHaveLength(1);
    const report = apiData.data[0]!;
    expect(report).toMatchObject({
      provider: "kimi-code",
      credentialId: pollResult.data!.id,
      accountLabel: ACCOUNT_ID,
      health: "healthy",
      source: "live",
    });
    expect(report.limits).toHaveLength(3);
    expect(report.limits.map(limit => limit.window?.id).sort()).toEqual(["5h", "7d", "monthly"]);

    const limit5h = report.limits.find(limit => limit.window?.id === "5h");
    expect(limit5h).toMatchObject({
      id: "kimi-code-5h",
      amount: { used: 30, remaining: 70, limit: 100, unit: "percent" },
      status: "ok",
      window: { id: "5h", durationMs: 5 * 60 * 60 * 1000, resetsAt: Date.parse("2027-09-26T18:00:00Z") },
    });
    const limit7d = report.limits.find(limit => limit.window?.id === "7d");
    expect(limit7d).toMatchObject({
      id: "kimi-code-7d",
      amount: { used: 20, remaining: 80, limit: 100, unit: "percent" },
      status: "ok",
      window: { id: "7d", durationMs: 7 * 24 * 60 * 60 * 1000, resetsAt: Date.parse("2027-10-03T00:00:00Z") },
    });
    const monthlyLimit = report.limits.find(limit => limit.window?.id === "monthly");
    expect(monthlyLimit).toMatchObject({
      id: "kimi-code-monthly",
      amount: { used: 40, remaining: 60, limit: 100, unit: "percent" },
      status: "ok",
      notes: ["Kod kullanımı: %25"],
      window: { id: "monthly", resetsAt: Date.parse("2027-10-01T00:00:00Z") },
    });
    expect(monthlyLimit?.window?.durationMs).toBeUndefined();
    expect(JSON.stringify(report)).not.toContain("boosterWallet");

    const reportJson = JSON.stringify(apiData);
    expect(reportJson).not.toContain(ACCESS_TOKEN);
    expect(reportJson).not.toContain(REFRESH_TOKEN);
    const usageResponse = await app.request("/api/usage", { headers: { Cookie: owner.cookie } });
    const usageJson = JSON.stringify(await usageResponse.json());
    expect(usageResponse.status).toBe(200);
    expect(usageJson).not.toContain(ACCESS_TOKEN);
    expect(usageJson).not.toContain(REFRESH_TOKEN);

    const credentialResponse = await app.request("/api/credentials", { headers: { Cookie: owner.cookie } });
    expect(credentialResponse.status).toBe(200);
    const credentialJson = await credentialResponse.json() as {
      data: Array<{ provider: string; maskedSecret: string }>;
    };
    expect(credentialJson.data).toHaveLength(1);
    expect(credentialJson.data[0]).toMatchObject({
      provider: "kimi-code",
      maskedSecret: `${ACCESS_TOKEN.slice(0, 4)}...${ACCESS_TOKEN.slice(-4)}`,
    });
    const credentialsJson = JSON.stringify(credentialJson);
    expect(credentialsJson).not.toContain(ACCESS_TOKEN);
    expect(credentialsJson).not.toContain(REFRESH_TOKEN);

    const otherCredentialsResponse = await app.request("/api/credentials", { headers: { Cookie: otherTenant.cookie } });
    expect(otherCredentialsResponse.status).toBe(200);
    expect((await otherCredentialsResponse.json() as { data: unknown[] }).data).toHaveLength(0);
    expect(fetchMock.calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `POST ${DEVICE_AUTHORIZATION_URL}`,
      `POST ${TOKEN_URL}`,
      `GET ${USAGES_URL}`,
    ]);
  });

  it("keeps an OAuth login connected for official empty usage and later polls quota on the same credential", async () => {
    const deviceCode = "synthetic-kimi-device-empty";
    const { app, vault, fetchMock } = createHarness(
      {},
      deviceCode,
    );
    const owner = await registerUser(app, "kimi-empty@example.com");

    const initiateResponse = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    expect(initiateResponse.status).toBe(200);
    const initiateBody = await initiateResponse.json() as { data: { deviceCode: string; deviceId: string } };
    const pollResponse = await app.request(
      "/api/oauth/kimi/poll",
      authenticatedJson(owner.cookie, initiateBody.data),
    );
    expect(pollResponse.status).toBe(200);
    const pollResult = await pollResponse.json() as { status: string; data?: { id: string; accountLabel: string } };
    expect(pollResult).toMatchObject({ status: "complete", data: { accountLabel: ACCOUNT_ID } });

    const credentialId = pollResult.data!.id;
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    expect(vault.getCredential(owner.userId, credentialId)).toMatchObject({
      provider: "kimi-code",
      credentialType: "oauth",
      secret: ACCESS_TOKEN,
      metadata: { refreshToken: REFRESH_TOKEN, accountId: ACCOUNT_ID },
    });

    const emptyDataResponse = await app.request("/api/data", { headers: { Cookie: owner.cookie } });
    expect(emptyDataResponse.status).toBe(200);
    const emptyData = await emptyDataResponse.json() as {
      success: boolean;
      data: Array<Record<string, unknown> & { limits: unknown[] }>;
    };
    expect(emptyData.success).toBe(true);
    expect(emptyData.data).toHaveLength(1);
    const emptyReport = emptyData.data[0]!;
    expect(emptyReport).toMatchObject({
      provider: "kimi-code",
      credentialId,
      accountLabel: ACCOUNT_ID,
      health: "healthy",
      source: "live",
      metadata: { accountId: ACCOUNT_ID },
      limits: [],
    });
    expect(emptyReport["error"]).toBeUndefined();
    const emptyReportJson = JSON.stringify(emptyReport);
    expect(emptyReportJson).not.toContain(ACCESS_TOKEN);
    expect(emptyReportJson).not.toContain(REFRESH_TOKEN);
    expect(emptyReportJson).not.toContain("refreshToken");

    fetchMock.usagePayload = OFFICIAL_USAGE_PAYLOAD;
    const laterPollResponse = await app.request(
      `/api/credentials/${credentialId}/poll`,
      authenticatedJson(owner.cookie),
    );
    expect(laterPollResponse.status).toBe(200);
    const laterPoll = await laterPollResponse.json() as {
      success: boolean;
      data: { credentialId: string; limits: unknown[]; health: string; source: string };
    };
    expect(laterPoll).toMatchObject({
      success: true,
      data: {
        credentialId,
        health: "healthy",
        source: "live",
      },
    });
    expect(laterPoll.data.limits).toHaveLength(3);
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);

    const updatedDataResponse = await app.request("/api/data", { headers: { Cookie: owner.cookie } });
    const updatedData = await updatedDataResponse.json() as {
      data: Array<{ credentialId: string; limits: unknown[] }>;
    };
    expect(updatedData.data).toHaveLength(1);
    expect(updatedData.data[0]?.credentialId).toBe(credentialId);
    expect(Array.isArray(updatedData.data[0]?.limits)).toBe(true);
    expect(updatedData.data[0]?.limits).toHaveLength(3);
    expect(fetchMock.calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `POST ${DEVICE_AUTHORIZATION_URL}`,
      `POST ${TOKEN_URL}`,
      `GET ${USAGES_URL}`,
      `GET ${USAGES_URL}`,
    ]);
  });

  it("rolls back the OAuth credential when initial Kimi usage is unauthorized", async () => {
    const deviceCode = "synthetic-kimi-device-unauthorized";
    const { app, vault, fetchMock } = createHarness({}, deviceCode, 403);
    const owner = await registerUser(app, "kimi-unauthorized@example.com");

    const initiateResponse = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    expect(initiateResponse.status).toBe(200);
    const initiateBody = await initiateResponse.json() as { data: { deviceCode: string; deviceId: string } };
    const pollResponse = await app.request(
      "/api/oauth/kimi/poll",
      authenticatedJson(owner.cookie, initiateBody.data),
    );
    expect(pollResponse.status).toBe(200);
    const pollResult = await pollResponse.json() as { status: string };
    expect(pollResult.status).toBe("error");
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(0);
    expect(fetchMock.calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `POST ${DEVICE_AUTHORIZATION_URL}`,
      `POST ${TOKEN_URL}`,
      `GET ${USAGES_URL}`,
    ]);
  });

  it("rejects an unsupported HTTP 200 usage schema and rolls back the newly authorized credential", async () => {
    const deviceCode = "synthetic-kimi-device-unsupported";
    const unsupportedPayload = {
      goods_version: 2,
      usages: {
        limit_5h: { used_ratio: "not-a-number", reset_time: "2027-09-26T18:00:00Z" },
        limit_7d: { unavailable: true },
        limit_month_total: { used_ratio: null },
      },
    };
    const { app, vault, fetchMock } = createHarness(unsupportedPayload, deviceCode);
    const owner = await registerUser(app, "kimi-rollback@example.com");

    const initiateResponse = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    expect(initiateResponse.status).toBe(200);
    const initiateBody = await initiateResponse.json() as { data: { deviceCode: string; deviceId: string } };

    const pollResponse = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initiateBody.data));
    expect(pollResponse.status).toBe(200);
    const pollResult = await pollResponse.json() as { status: string };
    expect(pollResult.status).toBe("error");
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(0);

    const credentialResponse = await app.request("/api/credentials", { headers: { Cookie: owner.cookie } });
    expect((await credentialResponse.json() as { data: unknown[] }).data).toHaveLength(0);
    const dataResponse = await app.request("/api/data", { headers: { Cookie: owner.cookie } });
    expect((await dataResponse.json() as { data: unknown[] }).data).toHaveLength(0);
    expect(fetchMock.calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `POST ${DEVICE_AUTHORIZATION_URL}`,
      `POST ${TOKEN_URL}`,
      `GET ${USAGES_URL}`,
    ]);
  });

  it("preserves existing credential, secret, refresh token, accent, and snapshot history when repeat OAuth fails with 403 or malformed 200", async () => {
    const initialDeviceCode = "synthetic-kimi-device-initial-good";
    const { app, vault, fetchMock } = createHarness(OFFICIAL_USAGE_PAYLOAD, initialDeviceCode);
    const owner = await registerUser(app, "kimi-preserve-history@example.com");

    const initRes1 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    expect(initRes1.status).toBe(200);
    const initData1 = await initRes1.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes1 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData1.data));
    expect(pollRes1.status).toBe(200);
    const pollResult1 = await pollRes1.json() as { status: string; data?: { id: string } };
    expect(pollResult1.status).toBe("complete");
    const credentialId = pollResult1.data!.id;

    // Customize accent and seed an additional prior usage snapshot
    expect(vault.updateCredential(owner.userId, credentialId, { accent: "emerald" })).toBe(true);
    const baselineCred = vault.getCredential(owner.userId, credentialId);
    expect(baselineCred).not.toBeNull();
    expect(baselineCred?.accent).toBe("emerald");
    expect(baselineCred?.secret).toBe(ACCESS_TOKEN);
    expect(baselineCred?.metadata).toMatchObject({
      refreshToken: REFRESH_TOKEN,
      accountId: ACCOUNT_ID,
    });

    const priorSnapshotTime = Date.now() - 3600_000;
    vault.saveUsageSnapshot(owner.userId, {
      provider: "kimi-code",
      credentialId,
      accountLabel: ACCOUNT_ID,
      fetchedAt: priorSnapshotTime,
      health: "healthy",
      source: "live",
      limits: [],
    });

    const baselineSnapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(baselineSnapshots.length).toBeGreaterThanOrEqual(2);

    // Repeat attempt 1: 403 forbidden on usage fetch
    fetchMock.deviceCode = "synthetic-kimi-device-repeat-403";
    fetchMock.usageStatus = 403;
    fetchMock.accessToken = REPEAT_ACCESS_TOKEN;
    fetchMock.refreshToken = REPEAT_REFRESH_TOKEN;

    const initRes2 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData2 = await initRes2.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes2 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData2.data));
    expect(pollRes2.status).toBe(200);
    const pollResult2 = await pollRes2.json() as { status: string };
    expect(pollResult2.status).toBe("error");

    // Existing credential and snapshots MUST remain intact
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    const credAfter403 = vault.getCredential(owner.userId, credentialId);
    expect(credAfter403).not.toBeNull();
    expect(credAfter403?.secret).toBe(ACCESS_TOKEN);
    expect(credAfter403?.metadata?.["refreshToken"]).toBe(REFRESH_TOKEN);
    expect(credAfter403?.accent).toBe("emerald");
    expect(vault.getSnapshotHistory(owner.userId, "kimi-code", 24)).toHaveLength(baselineSnapshots.length);

    // Repeat attempt 2: malformed 200 payload
    fetchMock.deviceCode = "synthetic-kimi-device-repeat-malformed";
    fetchMock.usageStatus = 200;
    fetchMock.usagePayload = {
      usages: {
        limit_5h: { used_ratio: "invalid-number" },
      },
    };

    const initRes3 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData3 = await initRes3.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes3 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData3.data));
    expect(pollRes3.status).toBe(200);
    const pollResult3 = await pollRes3.json() as { status: string };
    expect(pollResult3.status).toBe("error");

    // Existing credential and snapshots STILL preserved
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    const credAfterMalformed = vault.getCredential(owner.userId, credentialId);
    expect(credAfterMalformed?.secret).toBe(ACCESS_TOKEN);
    expect(credAfterMalformed?.metadata?.["refreshToken"]).toBe(REFRESH_TOKEN);
    expect(credAfterMalformed?.accent).toBe("emerald");
    expect(vault.getSnapshotHistory(owner.userId, "kimi-code", 24)).toHaveLength(baselineSnapshots.length);
  });

  it("replaces token, preserves history and accent, appends exactly one snapshot, and calls /usages once when repeat OAuth succeeds", async () => {
    const initialDeviceCode = "synthetic-kimi-device-initial-for-success";
    const { app, vault, fetchMock } = createHarness(OFFICIAL_USAGE_PAYLOAD, initialDeviceCode);
    const owner = await registerUser(app, "kimi-repeat-success@example.com");

    const initRes1 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData1 = await initRes1.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes1 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData1.data));
    expect(pollRes1.status).toBe(200);
    const pollResult1 = await pollRes1.json() as { status: string; data?: { id: string } };
    expect(pollResult1.status).toBe("complete");
    const credentialId = pollResult1.data!.id;

    // Set accent
    expect(vault.updateCredential(owner.userId, credentialId, { accent: "cyan" })).toBe(true);
    const snapshotsBeforeRepeat = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(snapshotsBeforeRepeat).toHaveLength(1);

    // Configure repeat with new tokens and fresh official usage
    fetchMock.deviceCode = "synthetic-kimi-device-repeat-success";
    fetchMock.usageStatus = 200;
    fetchMock.usagePayload = OFFICIAL_USAGE_PAYLOAD;
    fetchMock.accessToken = REPEAT_ACCESS_TOKEN;
    fetchMock.refreshToken = REPEAT_REFRESH_TOKEN;

    const callsBeforeRepeat = fetchMock.calls.length;

    const initRes2 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData2 = await initRes2.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes2 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData2.data));
    expect(pollRes2.status).toBe(200);
    const pollResult2 = await pollRes2.json() as { status: string; data?: { id: string } };
    expect(pollResult2.status).toBe("complete");
    expect(pollResult2.data?.id).toBe(credentialId);

    // Credential was updated, NOT duplicated
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    const updatedCred = vault.getCredential(owner.userId, credentialId);
    expect(updatedCred).not.toBeNull();
    expect(updatedCred?.secret).toBe(REPEAT_ACCESS_TOKEN);
    expect(updatedCred?.metadata?.["refreshToken"]).toBe(REPEAT_REFRESH_TOKEN);
    expect(updatedCred?.accent).toBe("cyan");

    // Snapshot history has exactly one new snapshot appended
    const snapshotsAfterRepeat = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(snapshotsAfterRepeat).toHaveLength(snapshotsBeforeRepeat.length + 1);

    // During this repeat authorization flow, /usages was called exactly ONCE
    const repeatCalls = fetchMock.calls.slice(callsBeforeRepeat);
    const usageCalls = repeatCalls.filter(call => call.url === USAGES_URL);
    expect(usageCalls).toHaveLength(1);
  });

  it("preserves old refreshToken and history when repeat OAuth succeeds without a new refresh_token", async () => {
    const initialDeviceCode = "synthetic-kimi-device-initial-for-no-refresh";
    const { app, vault, fetchMock } = createHarness(OFFICIAL_USAGE_PAYLOAD, initialDeviceCode);
    const owner = await registerUser(app, "kimi-no-refresh@example.com");

    const initRes1 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData1 = await initRes1.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes1 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData1.data));
    expect(pollRes1.status).toBe(200);
    const pollResult1 = await pollRes1.json() as { status: string; data?: { id: string } };
    expect(pollResult1.status).toBe("complete");
    const credentialId = pollResult1.data!.id;

    // Verify initial credential has REFRESH_TOKEN
    const initialCred = vault.getCredential(owner.userId, credentialId);
    expect(initialCred?.secret).toBe(ACCESS_TOKEN);
    expect(initialCred?.metadata?.["refreshToken"]).toBe(REFRESH_TOKEN);
    const initialSnapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(initialSnapshots).toHaveLength(1);

    // Repeat authorization: new access token, but NO refresh_token returned by upstream
    fetchMock.deviceCode = "synthetic-kimi-device-repeat-no-refresh";
    fetchMock.usageStatus = 200;
    fetchMock.usagePayload = OFFICIAL_USAGE_PAYLOAD;
    fetchMock.accessToken = REPEAT_ACCESS_TOKEN;
    fetchMock.refreshToken = null; // omits refresh_token from token JSON response

    const initRes2 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData2 = await initRes2.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes2 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData2.data));
    expect(pollRes2.status).toBe(200);
    const pollResult2 = await pollRes2.json() as { status: string; data?: { id: string } };
    expect(pollResult2.status).toBe("complete");
    expect(pollResult2.data?.id).toBe(credentialId);

    // New secret applied, but OLD refresh token preserved!
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    const updatedCred = vault.getCredential(owner.userId, credentialId);
    expect(updatedCred?.secret).toBe(REPEAT_ACCESS_TOKEN);
    expect(updatedCred?.metadata?.["refreshToken"]).toBe(REFRESH_TOKEN);

    // Snapshot history preserved and appended
    const updatedSnapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(updatedSnapshots).toHaveLength(initialSnapshots.length + 1);
  });

  it("rejects repeat OAuth with 401 when new token is invalid and no replacement refresh token was returned, without calling refresh endpoint or corrupting old credential", async () => {
    const initialDeviceCode = "synthetic-kimi-device-initial-for-401-isolation";
    const { app, vault, fetchMock } = createHarness(OFFICIAL_USAGE_PAYLOAD, initialDeviceCode);
    const owner = await registerUser(app, "kimi-401-isolation@example.com");

    const initRes1 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData1 = await initRes1.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes1 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData1.data));
    expect(pollRes1.status).toBe(200);
    const pollResult1 = await pollRes1.json() as { status: string; data?: { id: string } };
    expect(pollResult1.status).toBe("complete");
    const credentialId = pollResult1.data!.id;

    // Verify baseline credential
    const baselineCred = vault.getCredential(owner.userId, credentialId);
    expect(baselineCred?.secret).toBe(ACCESS_TOKEN);
    expect(baselineCred?.metadata?.["refreshToken"]).toBe(REFRESH_TOKEN);
    const baselineSnapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(baselineSnapshots).toHaveLength(1);

    const callsBeforeRepeat = fetchMock.calls.length;

    // Repeat authorization returns a new invalid access token and NO new refresh token.
    // Provider returns 401 on /usages.
    fetchMock.deviceCode = "synthetic-kimi-device-repeat-401";
    fetchMock.usageStatus = 401;
    fetchMock.accessToken = "synthetic-invalid-new-access-token";
    fetchMock.refreshToken = null; // omits refresh_token from token exchange response

    const initRes2 = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData2 = await initRes2.json() as { data: { deviceCode: string; deviceId: string } };
    const pollRes2 = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData2.data));
    expect(pollRes2.status).toBe(200);
    const pollResult2 = await pollRes2.json() as { status: string };
    expect(pollResult2.status).toBe("error");

    // CRITICAL: Since candidate was staged with only new token metadata, it MUST NOT
    // have merged the old refreshToken before validation. Therefore, it must NEVER have attempted
    // to call the refresh endpoint to refresh using the old token.
    const callsDuringRepeat = fetchMock.calls.slice(callsBeforeRepeat);
    const refreshCalls = callsDuringRepeat.filter(call => call.url === TOKEN_URL && call.method === "POST");
    // Token endpoint is called once for device_code grant exchange, but ZERO times for refresh_token grant
    expect(refreshCalls).toHaveLength(1); // the device code exchange only

    // Old credential, secret, refreshToken, and snapshot history MUST be intact!
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    const credAfterFailure = vault.getCredential(owner.userId, credentialId);
    expect(credAfterFailure?.secret).toBe(ACCESS_TOKEN);
    expect(credAfterFailure?.metadata?.["refreshToken"]).toBe(REFRESH_TOKEN);
    expect(vault.getSnapshotHistory(owner.userId, "kimi-code", 24)).toHaveLength(1);
  });

  it("guards against in-flight polls on old secret: stale in-flight poll cannot overwrite new token or write stale snapshot after reauth commit", async () => {
    const initialDeviceCode = "synthetic-kimi-device-initial-for-race";
    const { app, vault, poller, registry } = createHarness(OFFICIAL_USAGE_PAYLOAD, initialDeviceCode);
    const owner = await registerUser(app, "kimi-race-guard@example.com");

    // Save an initial credential
    const initialCred = vault.saveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: "Race Account",
      credentialType: "oauth",
      secret: "old-initial-access-token",
      metadata: { refreshToken: "old-refresh-token", accountId: "kimi-race" },
    });
    vault.saveUsageSnapshot(owner.userId, {
      provider: "kimi-code",
      credentialId: initialCred.id,
      accountLabel: initialCred.accountLabel,
      fetchedAt: Date.now() - 10_000,
      limits: [],
      health: "healthy",
      source: "live",
    });

    const baselineSnapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(baselineSnapshots).toHaveLength(1);

    // Create a deferred adapter that pauses in-flight poll on the old secret
    let resumeOldPoll!: () => void;
    const oldPollPaused = Promise.withResolvers<void>();
    const oldPollCanFinish = new Promise<void>(resolve => {
      resumeOldPoll = resolve;
    });

    let oldPollAttemptedTokenRefresh = false;

    // We replace the adapter in registry with a controlled mock that wraps fetchUsage
    const originalAdapter = registry.find("kimi-code")!;
    const mockAdapter = {
      id: "kimi-code",
      supports: (p: string) => originalAdapter.supports(p),
      fetchUsage: async (cred: StoredCredential, ctx?: FetchContext): Promise<UsageReport> => {
        if (cred.secret === "old-initial-access-token") {
          // Notify that old poll has started and is now suspended
          oldPollPaused.resolve();
          // Wait until reauth finishes
          await oldPollCanFinish;
          // Attempt to call onTokenRefresh on the stale poll
          ctx?.onTokenRefresh?.("stale-refreshed-secret-should-be-dropped", { refreshToken: "stale-refresh" });
          oldPollAttemptedTokenRefresh = true;
          return {
            provider: "kimi-code",
            credentialId: cred.id,
            accountLabel: cred.accountLabel,
            fetchedAt: Date.now(),
            limits: [],
            health: "healthy",
            source: "live",
          };
        }
        // For the new candidate during validateAndSaveCredential
        return {
          provider: "kimi-code",
          credentialId: cred.id,
          accountLabel: cred.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          source: "live",
        };
      },
    };

    // Replace adapter in registry for this test
    const allAdapters = registry.all() as ProviderAdapter[];
    const adapterIndex = allAdapters.findIndex(a => a.id === "kimi-code");
    allAdapters[adapterIndex] = mockAdapter as unknown as ProviderAdapter;

    // 1. Start the background/daemon poll on old secret (does not await yet)
    const backgroundPollPromise = poller.pollCredential(owner.userId, initialCred.id);

    // 2. Wait until old poll is actively suspended inside fetchUsage
    await oldPollPaused.promise;

    // 3. User commits staged reauth with new token while old poll is still in flight!
    const reauthCred = await poller.validateAndSaveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: "Race Account",
      credentialType: "oauth",
      secret: "new-reauthorized-access-token",
      metadata: { refreshToken: "new-refresh-token", accountId: "kimi-race" },
    }, "preserve");
    expect(reauthCred.id).toBe(initialCred.id);
    expect(vault.getCredential(owner.userId, initialCred.id)?.secret).toBe("new-reauthorized-access-token");
    expect(vault.getSnapshotHistory(owner.userId, "kimi-code", 24)).toHaveLength(2);

    // 4. Now let the suspended old poll resume and try to finish
    resumeOldPoll();
    const oldPollResult = await backgroundPollPromise;

    // Old poll result must be dropped (null) because credential epoch was bumped
    expect(oldPollResult).toBeNull();
    expect(oldPollAttemptedTokenRefresh).toBe(true);

    // 5. Assert: new secret was NOT overwritten by the old poll's onTokenRefresh!
    const currentCred = vault.getCredential(owner.userId, initialCred.id);
    expect(currentCred?.secret).toBe("new-reauthorized-access-token");
    expect(currentCred?.metadata?.["refreshToken"]).toBe("new-refresh-token");

    // 6. Assert: old poll did NOT write a 3rd stale snapshot!
    expect(vault.getSnapshotHistory(owner.userId, "kimi-code", 24)).toHaveLength(2);
  });

  it("dispatches exactly one provider fetch, one persisted snapshot, and one listener event on successful authorization", async () => {
    const deviceCode = "synthetic-kimi-device-single-flight";
    const { app, vault, poller, fetchMock } = createHarness(OFFICIAL_USAGE_PAYLOAD, deviceCode);
    const owner = await registerUser(app, "kimi-single-flight@example.com");

    const reportsReceived: UsageReport[] = [];
    const unsubscribe = poller.onReport(report => {
      reportsReceived.push(report);
    });
    cleanups.push(unsubscribe);

    const initRes = await app.request("/api/oauth/kimi/initiate", authenticatedJson(owner.cookie));
    const initData = await initRes.json() as { data: { deviceCode: string; deviceId: string } };

    const callsBeforePoll = fetchMock.calls.length;
    const pollRes = await app.request("/api/oauth/kimi/poll", authenticatedJson(owner.cookie, initData.data));
    expect(pollRes.status).toBe(200);
    const pollResult = await pollRes.json() as { status: string; data?: { id: string } };
    expect(pollResult.status).toBe("complete");

    // Exactly 1 usage fetch from provider
    const usageCalls = fetchMock.calls.slice(callsBeforePoll).filter(call => call.url === USAGES_URL);
    expect(usageCalls).toHaveLength(1);

    // Exactly 1 snapshot in history
    const snapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(snapshots).toHaveLength(1);

    // Exactly 1 listener notification
    expect(reportsReceived).toHaveLength(1);
    expect(reportsReceived[0]?.credentialId).toBe(pollResult.data!.id);
  });

  it("preserves rotated refresh token R1 when old poll rotates R0 to R1 during deferred candidate validation without a new refresh token", async () => {
    const deviceCode = "synthetic-kimi-device-deferred-r1";
    const { app, vault, poller, registry } = createHarness(OFFICIAL_USAGE_PAYLOAD, deviceCode);
    const owner = await registerUser(app, "kimi-deferred-r1@example.com");

    // 1. Initial credential with refresh token R0
    const initialCred = vault.saveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: ACCOUNT_ID,
      credentialType: "oauth",
      secret: ACCESS_TOKEN,
      metadata: { refreshToken: "R0", accountId: ACCOUNT_ID },
      accent: "violet",
    });
    vault.saveUsageSnapshot(owner.userId, {
      provider: "kimi-code",
      credentialId: initialCred.id,
      accountLabel: initialCred.accountLabel,
      fetchedAt: Date.now() - 60_000,
      limits: [],
      health: "healthy",
      source: "live",
    });

    const baselineSnapshots = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(baselineSnapshots).toHaveLength(1);

    // 2. Set up deferred mock adapter
    let candidateUsageCalls = 0;
    let candidateReceivedOldToken = false;
    let resumeCandidate!: () => void;
    const candidatePending = Promise.withResolvers<void>();
    const candidateCanComplete = new Promise<void>(resolve => {
      resumeCandidate = resolve;
    });

    const originalAdapter = registry.find("kimi-code")!;
    const mockAdapter: ProviderAdapter = {
      id: "kimi-code",
      supports: (p: string) => originalAdapter.supports(p),
      fetchUsage: async (cred: StoredCredential, ctx?: FetchContext): Promise<UsageReport> => {
        if (cred.secret === "candidate-access-token-new") {
          candidateUsageCalls += 1;
          // CRITICAL: candidate MUST NOT get old refresh token R0 before fetch!
          if (cred.metadata?.["refreshToken"]) {
            candidateReceivedOldToken = true;
          }
          // Pause candidate validation
          candidatePending.resolve();
          await candidateCanComplete;

          // Return valid report with NO new refresh token
          return {
            provider: "kimi-code",
            credentialId: cred.id,
            accountLabel: cred.accountLabel,
            fetchedAt: Date.now(),
            limits: [],
            health: "healthy",
            source: "live",
          };
        }
        return originalAdapter.fetchUsage(cred, ctx);
      },
    };

    const allAdapters = registry.all() as ProviderAdapter[];
    const adapterIndex = allAdapters.findIndex(a => a.id === "kimi-code");
    allAdapters[adapterIndex] = mockAdapter;

    // 3. Start candidate validation in background (does not provide a new refreshToken)
    const candidatePromise = poller.validateAndSaveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: ACCOUNT_ID,
      credentialType: "oauth",
      secret: "candidate-access-token-new",
      metadata: { accountId: ACCOUNT_ID }, // NO refreshToken provided by new OAuth response
    }, "preserve");

    // 4. Wait until candidate validation is actively pending inside fetchUsage
    await candidatePending.promise;
    expect(candidateUsageCalls).toBe(1);
    expect(candidateReceivedOldToken).toBe(false);

    // 5. While candidate is pending, old background poll rotates refresh token from R0 to R1!
    const rotateSuccess = vault.updateCredentialTokens(owner.userId, initialCred.id, "rotated-access-token", {
      refreshToken: "R1",
    });
    expect(rotateSuccess).toBe(true);
    const credDuringWait = vault.getCredential(owner.userId, initialCred.id);
    expect(credDuringWait?.metadata?.["refreshToken"]).toBe("R1");

    // 6. Resume candidate validation and await completion
    resumeCandidate();
    const savedCred = await candidatePromise;

    // 7. Verify:
    // - Saved credential retains original ID
    expect(savedCred.id).toBe(initialCred.id);
    // - New access token applied
    expect(savedCred.secret).toBe("candidate-access-token-new");
    // - Rotated R1 preserved (NOT overwritten by R0 or wiped out!)
    expect(savedCred.metadata?.["refreshToken"]).toBe("R1");
    // - Original accent preserved
    expect(savedCred.accent).toBe("violet");
    // - Exactly 1 candidate GET happened (no extra provider GET)
    expect(candidateUsageCalls).toBe(1);
    // - Total credentials count is still 1 (no duplicate)
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(1);
    // - Snapshot history preserved and appended (no data deleted)
    const snapshotsAfter = vault.getSnapshotHistory(owner.userId, "kimi-code", 24);
    expect(snapshotsAfter).toHaveLength(2);
    expect(snapshotsAfter[0]?.credentialId).toBe(initialCred.id);
    expect(snapshotsAfter[1]?.credentialId).toBe(initialCred.id);
  });

  it("aborts candidate commit when existing credential row is deleted during validation await", async () => {
    const deviceCode = "synthetic-kimi-device-abort-delete";
    const { app, vault, poller, registry } = createHarness(OFFICIAL_USAGE_PAYLOAD, deviceCode);
    const owner = await registerUser(app, "kimi-abort-delete@example.com");

    const initialCred = vault.saveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: "Kimi To Delete",
      credentialType: "oauth",
      secret: ACCESS_TOKEN,
      metadata: { refreshToken: "R0", accountId: ACCOUNT_ID },
    });

    let resumeCandidate!: () => void;
    const candidatePending = Promise.withResolvers<void>();
    const candidateCanComplete = new Promise<void>(resolve => {
      resumeCandidate = resolve;
    });

    const originalAdapter = registry.find("kimi-code")!;
    const mockAdapter: ProviderAdapter = {
      id: "kimi-code",
      supports: (p: string) => originalAdapter.supports(p),
      fetchUsage: async (cred: StoredCredential, ctx?: FetchContext): Promise<UsageReport> => {
        if (cred.secret === "abort-delete-access-token") {
          candidatePending.resolve();
          await candidateCanComplete;
          return {
            provider: "kimi-code",
            credentialId: cred.id,
            accountLabel: cred.accountLabel,
            fetchedAt: Date.now(),
            limits: [],
            health: "healthy",
            source: "live",
          };
        }
        return originalAdapter.fetchUsage(cred, ctx);
      },
    };

    const allAdapters = registry.all() as ProviderAdapter[];
    const adapterIndex = allAdapters.findIndex(a => a.id === "kimi-code");
    allAdapters[adapterIndex] = mockAdapter;

    const candidatePromise = poller.validateAndSaveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: "Kimi To Delete",
      credentialType: "oauth",
      secret: "abort-delete-access-token",
      metadata: { accountId: ACCOUNT_ID },
    }, "preserve");

    await candidatePending.promise;

    // Row is deleted while candidate validation is in flight
    vault.deleteCredential(owner.userId, initialCred.id);
    expect(vault.getCredential(owner.userId, initialCred.id)).toBeNull();

    resumeCandidate();

    // Must reject/abort rather than recreate/duplicate row
    await expect(candidatePromise).rejects.toThrow("Credential changed while validation was in progress");
    expect(vault.listCredentials(owner.userId, "kimi-code")).toHaveLength(0);
  });

  it("aborts candidate commit when existing credential row is renamed during validation await", async () => {
    const deviceCode = "synthetic-kimi-device-abort-rename";
    const { app, vault, poller, registry } = createHarness(OFFICIAL_USAGE_PAYLOAD, deviceCode);
    const owner = await registerUser(app, "kimi-abort-rename@example.com");

    const initialCred = vault.saveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: "Original Label",
      credentialType: "oauth",
      secret: ACCESS_TOKEN,
      metadata: { refreshToken: "R0", accountId: ACCOUNT_ID },
    });

    let resumeCandidate!: () => void;
    const candidatePending = Promise.withResolvers<void>();
    const candidateCanComplete = new Promise<void>(resolve => {
      resumeCandidate = resolve;
    });

    const originalAdapter = registry.find("kimi-code")!;
    const mockAdapter: ProviderAdapter = {
      id: "kimi-code",
      supports: (p: string) => originalAdapter.supports(p),
      fetchUsage: async (cred: StoredCredential, ctx?: FetchContext): Promise<UsageReport> => {
        if (cred.secret === "abort-rename-access-token") {
          candidatePending.resolve();
          await candidateCanComplete;
          return {
            provider: "kimi-code",
            credentialId: cred.id,
            accountLabel: cred.accountLabel,
            fetchedAt: Date.now(),
            limits: [],
            health: "healthy",
            source: "live",
          };
        }
        return originalAdapter.fetchUsage(cred, ctx);
      },
    };

    const allAdapters = registry.all() as ProviderAdapter[];
    const adapterIndex = allAdapters.findIndex(a => a.id === "kimi-code");
    allAdapters[adapterIndex] = mockAdapter;

    const candidatePromise = poller.validateAndSaveCredential(owner.userId, {
      provider: "kimi-code",
      accountLabel: "Original Label",
      credentialType: "oauth",
      secret: "abort-rename-access-token",
      metadata: { accountId: ACCOUNT_ID },
    }, "preserve");

    await candidatePending.promise;

    // Row is renamed while candidate validation is in flight
    vault.updateCredentialLabel(owner.userId, initialCred.id, "Renamed Account");
    expect(vault.getCredential(owner.userId, initialCred.id)?.accountLabel).toBe("Renamed Account");

    resumeCandidate();

    // Must reject/abort rather than recreate/duplicate row
    await expect(candidatePromise).rejects.toThrow("Credential changed while validation was in progress");
    const creds = vault.listCredentials(owner.userId, "kimi-code");
    expect(creds).toHaveLength(1);
    expect(creds[0]?.accountLabel).toBe("Renamed Account");
    expect(creds[0]?.secret).toBe(ACCESS_TOKEN);
  });
});

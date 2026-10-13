import { describe, expect, it } from "bun:test";
import { KimiCodeAdapter } from "../src/core/providers/kimi-code";
import type { StoredCredential } from "../src/types";

const mockCred: StoredCredential = {
  id: "test-kimi-1",
  ownerId: "test-owner",
  provider: "kimi-code",
  accountLabel: "Kimi Tester",
  credentialType: "oauth",
  secret: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYiLCJleHAiOjE5OTk5OTk5OTl9.signature",
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

describe("KimiCodeAdapter usage limits and safe diagnostic schema clues", () => {
  it("rejects non-oauth credential types without attempting network calls", async () => {
    const adapter = new KimiCodeAdapter();
    expect(adapter.supports("kimi-code")).toBe(true);
    expect(adapter.supports("kimi")).toBe(true);
    expect(adapter.supports("moonshot")).toBe(true);

    let fetchCalled = false;
    const mockFetch = (async () => {
      fetchCalled = true;
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;

    await expect(
      adapter.fetchUsage({ ...mockCred, credentialType: "api_key", secret: "sk-plain-key" }, { fetch: mockFetch }),
    ).rejects.toThrow("Kimi Code kullanım sorgusu OAuth kimlik doğrulaması gerektirir");

    expect(fetchCalled).toBe(false);
  });

  it("handles valid usage limits correctly and produces a healthy usage report", async () => {
    const adapter = new KimiCodeAdapter();
    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          usage: {
            limit: 100,
            used: 25,
            remaining: 75,
            reset_time: "2026-10-01T00:00:00Z",
          },
          limits: [
            {
              detail: {
                limit: 50,
                used: 10,
                remaining: 40,
              },
              window: {
                duration: 5,
                timeUnit: "HOUR",
              },
            },
          ],
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("kimi-code");
    expect(report.limits.length).toBe(2);
    expect(report.limits[0]?.amount.used).toBe(25);
    expect(report.limits[0]?.amount.remaining).toBe(75);
    expect(report.limits[1]?.window?.id).toBe("5h");
  });

  it("fails authorization with standard message on HTTP 401 without emitting schema clues", async () => {
    const adapter = new KimiCodeAdapter();
    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          error: {
            message: "Unauthorized token",
            code: 401,
          },
        }),
        { status: 401, statusText: "Unauthorized" },
      );
    }) as unknown as typeof fetch;

    await expect(adapter.fetchUsage(mockCred, { fetch: mockFetch })).rejects.toThrow(
      "Kimi Code yetkilendirme hatası: HTTP 401",
    );
  });
  it("aborts a proactive refresh before token rotation or the usage request", async () => {
    const credential: StoredCredential = {
      ...mockCred,
      secret: `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({
        sub: "123456",
        exp: Math.floor(Date.now() / 1000) + 30,
        device_id: "synthetic-device-id",
      })).toString("base64url")}.signature`,
      metadata: { refreshToken: "original-kimi-refresh-token", deviceId: "synthetic-device-id" },
    };
    const originalSecret = credential.secret;
    const originalMetadata = credential.metadata;
    const controller = new AbortController();
    const refreshStarted = Promise.withResolvers<void>();
    let requests = 0;
    let persistedRefreshes = 0;
    const heldRefreshFetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      requests++;
      expect(init?.signal).toBe(controller.signal);
      refreshStarted.resolve();
      const signal = init?.signal as AbortSignal;
      return await new Promise<Response>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), { once: true });
      });
    }) as typeof fetch;

    const operation = new KimiCodeAdapter().fetchUsage(credential, {
      fetch: heldRefreshFetch,
      signal: controller.signal,
      onTokenRefresh: () => { persistedRefreshes++; },
    });
    await refreshStarted.promise;
    controller.abort();

    await expect(operation).rejects.toMatchObject({ name: "AbortError" });
    expect(requests).toBe(1);
    expect(credential.secret).toBe(originalSecret);
    expect(credential.metadata).toBe(originalMetadata);
    expect(persistedRefreshes).toBe(0);
  });

  it("aborts a 401-triggered refresh without a retry request or token rotation", async () => {
    const credential: StoredCredential = {
      ...mockCred,
      metadata: { refreshToken: "original-kimi-refresh-token", deviceId: "synthetic-device-id" },
    };
    const originalSecret = credential.secret;
    const originalMetadata = credential.metadata;
    const controller = new AbortController();
    const refreshStarted = Promise.withResolvers<void>();
    let requests = 0;
    let persistedRefreshes = 0;
    const heldRefreshFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      requests++;
      if (input.toString().endsWith("/usages")) {
        return new Response("{}", { status: 401 });
      }
      expect(input.toString()).toBe("https://auth.kimi.com/api/oauth/token");
      expect(init?.signal).toBe(controller.signal);
      refreshStarted.resolve();
      const signal = init?.signal as AbortSignal;
      return await new Promise<Response>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), { once: true });
      });
    }) as typeof fetch;

    const operation = new KimiCodeAdapter().fetchUsage(credential, {
      fetch: heldRefreshFetch,
      signal: controller.signal,
      onTokenRefresh: () => { persistedRefreshes++; },
    });
    await refreshStarted.promise;
    controller.abort();

    await expect(operation).rejects.toMatchObject({ name: "AbortError" });
    expect(requests).toBe(2);
    expect(credential.secret).toBe(originalSecret);
    expect(credential.metadata).toBe(originalMetadata);
    expect(persistedRefreshes).toBe(0);
  });


  it("includes sanitized structural clue on HTTP 200 with zero valid limits without leaking secrets, numeric quotas, or PII", async () => {
    const adapter = new KimiCodeAdapter();

    const secretTokenValue = "super-secret-refresh-token-xyz-12345";
    const userEmailValue = "private-user@example.com";
    const accountIdValue = "acc-998877665544";
    const exactNumericQuota = 847291;

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          code: 0,
          status: "success",
          data: {
            user_token: secretTokenValue,
            email_address: userEmailValue,
            account_id: accountIdValue,
            custom_dynamic_uuid_k8s: "dynamic-node-value",
            plan: "developer",
            quotas: [
              {
                name: "api_requests",
                scope: "daily",
                total_quota: exactNumericQuota,
                details: {
                  used_count: 1234,
                },
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    let thrownError: Error | undefined;
    try {
      await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    const msg = thrownError?.message ?? "";

    // Preserves existing Turkish prefix
    expect(msg).toContain("Kimi Code API geçerli bir kota veya limit verisi döndürmedi.");
    expect(msg).toContain("Şema ipucu:");

    // Emits safe structure and types
    expect(msg).toContain("$.code=number");
    expect(msg).toContain("$.status=string");
    expect(msg).toContain("$.data=object");
    expect(msg).toContain("$.data.plan=string");
    expect(msg).toContain("$.data.quotas=array");
    expect(msg).toContain("$.data.quotas[].name=string");
    expect(msg).toContain("$.data.quotas[].scope=string");

    // Dynamic or unknown key name is safely redacted
    expect(msg).toContain("$.data.[redacted-key]=string");
    expect(msg).not.toContain("custom_dynamic_uuid_k8s");

    // Strictly does not leak secret values, emails, account IDs, or raw quota numbers
    expect(msg).not.toContain(secretTokenValue);
    expect(msg).not.toContain(userEmailValue);
    expect(msg).not.toContain(accountIdValue);
    expect(msg).not.toContain(String(exactNumericQuota));
    expect(msg).not.toContain("1234");
    expect(msg).not.toContain("dynamic-node-value");
    expect(msg).not.toContain("developer");

    // Sensitive field keys themselves are skipped
    expect(msg).not.toContain("user_token");
    expect(msg).not.toContain("email_address");
    expect(msg).not.toContain("account_id");
  });

  it("strictly redacts prototype properties such as constructor and __proto__ without inheriting them", async () => {
    const adapter = new KimiCodeAdapter();

    const payload = JSON.parse(`{
      "data": {
        "constructor": { "subKey": "val" },
        "__proto__": { "polluted": true }
      }
    }`);

    const mockFetch = (async () => {
      return new Response(JSON.stringify(payload), { status: 200 });
    }) as unknown as typeof fetch;

    let thrownError: Error | undefined;
    try {
      await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    const msg = thrownError?.message ?? "";
    expect(msg).toContain("Şema ipucu:");
    expect(msg).toContain("$.data.[redacted-key]=object");
    expect(msg).not.toContain("$.data.constructor");
    expect(msg).not.toContain("$.data.__proto__");
  });

  it("returns an empty normalized report for an explicit empty JSON usage payload", async () => {
    const adapter = new KimiCodeAdapter();
    const mockFetch = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report).toMatchObject({
      provider: "kimi-code",
      credentialId: mockCred.id,
      accountLabel: mockCred.accountLabel,
      limits: [],
    });
  });

  it("accepts coherent empty managed usage with only optional official fields", async () => {
    const adapter = new KimiCodeAdapter();
    const payloads: unknown[] = [
      { usages: {} },
      { usages: {}, boosterWallet: null },
      { usages: {}, goods_version: 1 },
      { usages: {}, boosterWallet: null, goods_version: 2 },
    ];

    for (const payload of payloads) {
      const mockFetch = (async () => new Response(JSON.stringify(payload), { status: 200 })) as unknown as typeof fetch;
      const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
      expect(report.limits).toEqual([]);
    }
  });

  it("rejects error, unknown, and malformed payloads instead of treating them as empty usage", async () => {
    const adapter = new KimiCodeAdapter();
    const payloads: unknown[] = [
      { error: { message: "upstream error" } },
      { usages: {}, error: { message: "upstream error" } },
      { usages: {}, goods_version: 3 },
      { usages: {}, extraUsage: null },
      { usages: {}, boosterWallet: {} },
      { usages: { limit_5h: { used_ratio: "not-a-number" } } },
    ];

    for (const payload of payloads) {
      const mockFetch = (async () => new Response(JSON.stringify(payload), { status: 200 })) as unknown as typeof fetch;
      await expect(adapter.fetchUsage(mockCred, { fetch: mockFetch })).rejects.toThrow(
        "Kimi Code API geçerli bir kota veya limit verisi döndürmedi.",
      );
    }
  });

  it("identifies nonempty object containing only sensitive keys and emits 'yalnızca hassas anahtarlar içeren nesne' without leaking secrets or key names", async () => {
    const adapter = new KimiCodeAdapter();
    const sensitiveToken = "secret-token-value-999";
    const sensitiveSecret = "secret-credential-hash-888";

    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          user_token: sensitiveToken,
          authorization: sensitiveSecret,
          cookie: "session=abc",
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    let thrownError: Error | undefined;
    try {
      await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    const msg = thrownError?.message ?? "";
    expect(msg).toContain("Kimi Code API geçerli bir kota veya limit verisi döndürmedi.");
    expect(msg).toContain("Şema ipucu: yalnızca hassas anahtarlar içeren nesne");
    expect(msg).not.toContain(sensitiveToken);
    expect(msg).not.toContain(sensitiveSecret);
    expect(msg).not.toContain("user_token");
    expect(msg).not.toContain("authorization");
    expect(msg).not.toContain("cookie");
    expect(msg).not.toContain("session");
  });

  it("falls back to 'unsupported schema' if safe structural clues cannot be reliably extracted", async () => {
    const adapter = new KimiCodeAdapter();

    const problematicPayload = {};
    Object.defineProperty(problematicPayload, "problematicKey", {
      enumerable: true,
      get() {
        throw new Error("Getter read failed");
      },
    });

    const mockFetch = (async () => {
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        json: async () => problematicPayload,
      } as Response;
    }) as unknown as typeof fetch;

    let thrownError: Error | undefined;
    try {
      await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    expect(thrownError?.message).toContain("Şema ipucu: unsupported schema");
  });

  it("sends exactly first-party minimal Authorization and Accept headers to /coding/v1/usages, with no X-Msh or User-Agent headers", async () => {
    const adapter = new KimiCodeAdapter();
    let capturedHeaders: Record<string, string> = {};
    let capturedUrl = "";
    let capturedMethod = "";

    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = String(input);
      capturedMethod = init?.method ?? "GET";
      const headers = new Headers(init?.headers);
      capturedHeaders = Object.fromEntries(headers.entries());
      return new Response(
        JSON.stringify({
          usage: {
            limit: 100,
            used: 25,
            remaining: 75,
            reset_time: "2026-10-01T00:00:00Z",
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const testCred: StoredCredential = {
      ...mockCred,
      secret: "ey-test-bearer-token.payload.sig",
      metadata: {
        deviceId: "caller-device-id-should-not-leak-to-usages",
      },
    };

    const report = await adapter.fetchUsage(testCred, { fetch: mockFetch });
    expect(report.limits.length).toBeGreaterThan(0);
    expect(capturedUrl).toBe("https://api.kimi.com/coding/v1/usages");
    expect(capturedMethod).toBe("GET");

    expect(capturedHeaders["authorization"]).toBe("Bearer ey-test-bearer-token.payload.sig");
    expect(capturedHeaders["accept"]).toBe("application/json");

    expect(capturedHeaders["user-agent"]).toBeUndefined();
    expect(capturedHeaders["x-msh-platform"]).toBeUndefined();
    expect(capturedHeaders["x-msh-version"]).toBeUndefined();
    expect(capturedHeaders["x-msh-device-name"]).toBeUndefined();
    expect(capturedHeaders["x-msh-device-model"]).toBeUndefined();
    expect(capturedHeaders["x-msh-os-version"]).toBeUndefined();
    expect(capturedHeaders["x-msh-device-id"]).toBeUndefined();
  });

  it("sends exactly first-party minimal headers on 401 refresh retry request while preserving OAuth device headers during refresh", async () => {
    const adapter = new KimiCodeAdapter();
    const initialToken = "ey-expired-token.payload.sig";
    const refreshedToken = "ey-refreshed-token.payload.sig";
    const refreshToken = "test-refresh-token-12345";
    const deviceId = "test-device-id-abcde12345";

    let refreshCalled = false;
    let refreshHeaders: Record<string, string> = {};

    const usageCalls: Array<{ url: string; headers: Record<string, string> }> = [];
    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      if (url.includes("/api/oauth/token")) {
        refreshCalled = true;
        refreshHeaders = Object.fromEntries(headers.entries());
        return Response.json({
          access_token: refreshedToken,
          refresh_token: "new-refresh-token",
        });
      }
      usageCalls.push({
        url,
        headers: Object.fromEntries(headers.entries()),
      });

      if (usageCalls.length === 1) {
        return new Response(JSON.stringify({ error: "token_expired" }), { status: 401 });
      }

      return new Response(
        JSON.stringify({
          usages: {
            limit_5h: { used_ratio: 0.1, reset_time: "2026-09-11T18:00:00Z" },
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const cred: StoredCredential = {
      ...mockCred,
      secret: initialToken,
      metadata: {
        refreshToken,
        deviceId,
      },
    };

    const report = await adapter.fetchUsage(cred, { fetch: mockFetch });
    expect(report.limits.length).toBe(1);
    expect(refreshCalled).toBe(true);

    expect(refreshHeaders["x-msh-device-id"]).toBe(deviceId);
    expect(refreshHeaders["user-agent"]).toContain("KimiCLI");

    expect(usageCalls).toHaveLength(2);

    expect(usageCalls[0]?.headers["authorization"]).toBe(`Bearer ${initialToken}`);
    expect(usageCalls[0]?.headers["accept"]).toBe("application/json");
    expect(usageCalls[0]?.headers["x-msh-device-id"]).toBeUndefined();
    expect(usageCalls[0]?.headers["user-agent"]).toBeUndefined();

    expect(usageCalls[1]?.headers["authorization"]).toBe(`Bearer ${refreshedToken}`);
    expect(usageCalls[1]?.headers["accept"]).toBe("application/json");
    expect(usageCalls[1]?.headers["x-msh-device-id"]).toBeUndefined();
    expect(usageCalls[1]?.headers["user-agent"]).toBeUndefined();
  });

  it("parses official managed usages fixture with 5h, 7d, and monthly windows and breakdown note", async () => {
    const adapter = new KimiCodeAdapter();
    // Official MoonshotAI/kimi-code fixture: https://github.com/MoonshotAI/kimi-code/blob/main/packages/oauth/test/managed-usage.test.ts
    const officialPayload = {
      goods_version: 2,
      usages: {
        limit_5h: { used_ratio: 0.3, reset_time: "2026-09-11T18:00:00Z" },
        limit_7d: { used_ratio: 0.2, reset_time: "2026-09-17T00:00:00Z" },
        limit_month_total: { used_ratio: 0.4, reset_time: "2026-10-01T00:00:00Z" },
        limit_month_code: { used_ratio: 0.25, reset_time: "2026-10-01T00:00:00Z" },
      },
      boosterWallet: {
        balance: {
          type: "BOOSTER",
          amount: "20000000000",
          amountLeft: "10000000000",
        },
        monthlyChargeLimitEnabled: true,
        monthlyChargeLimit: { currency: "CNY", priceInCents: "20000" },
        monthlyUsed: { currency: "CNY", priceInCents: "5000" },
      },
    };

    const mockFetch = (async () => {
      return new Response(JSON.stringify(officialPayload), { status: 200 });
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.provider).toBe("kimi-code");
    // 3 limits: 5h, 7d, monthly total. month_code is a breakdown note on month_total, boosterWallet is not a quota.
    expect(report.limits.length).toBe(3);

    const limit5h = report.limits.find((l) => l.window?.id === "5h");
    expect(limit5h).toBeDefined();
    expect(limit5h?.id).toBe("kimi-code-5h");
    expect(limit5h?.label).toBe("5 Saatlik Kayan Kota");
    expect(limit5h?.amount.unit).toBe("percent");
    expect(limit5h?.amount.used).toBe(30);
    expect(limit5h?.amount.remaining).toBe(70);
    expect(limit5h?.amount.limit).toBe(100);
    expect(limit5h?.amount.usedFraction).toBe(0.3);
    expect(limit5h?.status).toBe("ok");
    expect(limit5h?.window?.durationMs).toBe(5 * 60 * 60 * 1000);
    expect(limit5h?.window?.resetsAt).toBe(Date.parse("2026-09-11T18:00:00Z"));

    const limit7d = report.limits.find((l) => l.window?.id === "7d");
    expect(limit7d).toBeDefined();
    expect(limit7d?.id).toBe("kimi-code-7d");
    expect(limit7d?.label).toBe("Haftalık Kota");
    expect(limit7d?.amount.used).toBe(20);
    expect(limit7d?.amount.remaining).toBe(80);
    expect(limit7d?.amount.limit).toBe(100);
    expect(limit7d?.amount.usedFraction).toBe(0.2);
    expect(limit7d?.status).toBe("ok");
    expect(limit7d?.window?.durationMs).toBe(7 * 24 * 60 * 60 * 1000);
    expect(limit7d?.window?.resetsAt).toBe(Date.parse("2026-09-17T00:00:00Z"));

    const limitMonth = report.limits.find((l) => l.window?.id === "monthly");
    expect(limitMonth).toBeDefined();
    expect(limitMonth?.id).toBe("kimi-code-monthly");
    expect(limitMonth?.label).toBe("Aylık Kota");
    expect(limitMonth?.amount.used).toBe(40);
    expect(limitMonth?.amount.remaining).toBe(60);
    expect(limitMonth?.amount.limit).toBe(100);
    expect(limitMonth?.amount.usedFraction).toBe(0.4);
    expect(limitMonth?.status).toBe("ok");
    // Calendar-variable: durationMs is undefined so 30d is not implied
    expect(limitMonth?.window?.durationMs).toBeUndefined();
    expect(limitMonth?.window?.resetsAt).toBe(Date.parse("2026-10-01T00:00:00Z"));
    expect(limitMonth?.notes).toEqual(["Kod kullanımı: %25"]);
  });

  it("parses partial payload containing only limit_5h and respects warning threshold", async () => {
    const adapter = new KimiCodeAdapter();
    const partialPayload = {
      usages: {
        limit_5h: { used_ratio: 0.85, reset_time: "2026-09-11T18:00:00Z" },
      },
    };

    const mockFetch = (async () => {
      return new Response(JSON.stringify(partialPayload), { status: 200 });
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.limits.length).toBe(1);
    const limit = report.limits[0];
    expect(limit?.id).toBe("kimi-code-5h");
    expect(limit?.amount.used).toBe(85);
    expect(limit?.amount.remaining).toBe(15);
    expect(limit?.amount.usedFraction).toBe(0.85);
    expect(limit?.status).toBe("warning");
  });

  it("handles ratio variations: decimal string, 0, 1 (exhausted), out-of-bounds clamping, and non-finite ratios", async () => {
    const adapter = new KimiCodeAdapter();

    // Decimal string and 0 ratio
    const mockFetch1 = (async () => {
      return new Response(
        JSON.stringify({
          usages: {
            limit_5h: { used_ratio: "0.50" },
            limit_7d: { used_ratio: 0 },
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const report1 = await adapter.fetchUsage(mockCred, { fetch: mockFetch1 });
    expect(report1.limits.length).toBe(2);
    expect(report1.limits[0]?.amount.used).toBe(50);
    expect(report1.limits[0]?.amount.remaining).toBe(50);
    expect(report1.limits[0]?.status).toBe("ok");
    expect(report1.limits[1]?.amount.used).toBe(0);
    expect(report1.limits[1]?.amount.remaining).toBe(100);
    expect(report1.limits[1]?.status).toBe("ok");

    // Ratio 1.0 and over-1 clamping (exhausted, healthy report)
    const mockFetch2 = (async () => {
      return new Response(
        JSON.stringify({
          usages: {
            limit_5h: { used_ratio: 1.0 },
            limit_7d: { used_ratio: 1.45 },
            limit_month_total: { used_ratio: -0.1 },
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const report2 = await adapter.fetchUsage(mockCred, { fetch: mockFetch2 });
    expect(report2.limits.length).toBe(3);
    expect(report2.limits[0]?.amount.used).toBe(100);
    expect(report2.limits[0]?.amount.remaining).toBe(0);
    expect(report2.limits[0]?.status).toBe("exhausted");
    // Clamped from 1.45 to 1.0
    expect(report2.limits[1]?.amount.used).toBe(100);
    expect(report2.limits[1]?.amount.remaining).toBe(0);
    expect(report2.limits[1]?.amount.usedFraction).toBe(1);
    expect(report2.limits[1]?.status).toBe("exhausted");
    // Clamped from -0.1 to 0
    expect(report2.limits[2]?.amount.used).toBe(0);
    expect(report2.limits[2]?.amount.remaining).toBe(100);
    expect(report2.limits[2]?.amount.usedFraction).toBe(0);
    expect(report2.limits[2]?.status).toBe("ok");

    // Non-finite values safely ignored
    const mockFetch3 = (async () => {
      return new Response(
        JSON.stringify({
          usages: {
            limit_5h: { used_ratio: "NaN" },
            limit_7d: { used_ratio: "Infinity" },
            limit_month_total: { used_ratio: null },
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    await expect(adapter.fetchUsage(mockCred, { fetch: mockFetch3 })).rejects.toThrow(
      "Kimi Code API geçerli bir kota veya limit verisi döndürmedi. Şema ipucu:",
    );
  });

  it("gracefully omits resetsAt when reset_time is malformed or invalid", async () => {
    const adapter = new KimiCodeAdapter();
    const mockFetch = (async () => {
      return new Response(
        JSON.stringify({
          usages: {
            limit_5h: { used_ratio: 0.3, reset_time: "not-an-iso-date" },
            limit_7d: { used_ratio: 0.4, reset_time: "2026-02-30T00:00:00Z" },
            limit_month_total: { used_ratio: 0.5, reset_time: "" },
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    expect(report.limits.length).toBe(3);
    expect(report.limits[0]?.window?.resetsAt).toBeUndefined();
    expect(report.limits[1]?.window?.resetsAt).toBeUndefined();
    expect(report.limits[2]?.window?.resetsAt).toBeUndefined();
  });

  it("prefers official usages over legacy payload without producing duplicate rows", async () => {
    const adapter = new KimiCodeAdapter();
    const hybridPayload = {
      usage: {
        limit: 100,
        used: 50,
        remaining: 50,
      },
      limits: [
        {
          detail: { limit: 100, used: 20, remaining: 80 },
          window: { duration: 5, timeUnit: "HOUR" },
        },
      ],
      usages: {
        limit_5h: { used_ratio: 0.25, reset_time: "2026-09-11T18:00:00Z" },
      },
    };

    const mockFetch = (async () => {
      return new Response(JSON.stringify(hybridPayload), { status: 200 });
    }) as unknown as typeof fetch;

    const report = await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    // Only official 5h limit is emitted, legacy fields are not duplicated
    expect(report.limits.length).toBe(1);
    expect(report.limits[0]?.id).toBe("kimi-code-5h");
    expect(report.limits[0]?.amount.used).toBe(25);
  });

  it("rejects payload containing only boosterWallet without fabricating fake limits", async () => {
    const adapter = new KimiCodeAdapter();
    const walletOnlyPayload = {
      goods_version: 1,
      boosterWallet: {
        balance: {
          type: "BOOSTER",
          amount: "20000000000",
          amountLeft: "10000000000",
        },
      },
    };

    const mockFetch = (async () => {
      return new Response(JSON.stringify(walletOnlyPayload), { status: 200 });
    }) as unknown as typeof fetch;

    let thrownError: Error | undefined;
    try {
      await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    const msg = thrownError?.message ?? "";
    expect(msg).toContain("Kimi Code API geçerli bir kota veya limit verisi döndürmedi. Şema ipucu:");
    expect(msg).toContain("boosterwallet");
    expect(msg).not.toContain(mockCred.secret);
  });

  it("fails authorization on HTTP 403 and rate limit on HTTP 429 without leaking credentials", async () => {
    const adapter = new KimiCodeAdapter();

    const mockFetch403 = (async () => {
      return new Response("Forbidden", { status: 403, statusText: "Forbidden" });
    }) as unknown as typeof fetch;

    await expect(adapter.fetchUsage(mockCred, { fetch: mockFetch403 })).rejects.toThrow(
      "Kimi Code yetkilendirme hatası: HTTP 403",
    );

    const mockFetch429 = (async () => {
      return new Response("Too Many Requests", { status: 429, statusText: "Too Many Requests" });
    }) as unknown as typeof fetch;

    await expect(adapter.fetchUsage(mockCred, { fetch: mockFetch429 })).rejects.toThrow(
      "Kimi Code kullanım sorgusu rate limit'e takıldı (HTTP 429).",
    );
  });

  it("does not leak secret tokens in JSON parsing errors", async () => {
    const adapter = new KimiCodeAdapter();
    const mockFetch = (async () => {
      return new Response("<html>Not JSON</html>", { status: 200 });
    }) as unknown as typeof fetch;

    let thrownError: Error | undefined;
    try {
      await adapter.fetchUsage(mockCred, { fetch: mockFetch });
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    const msg = thrownError?.message ?? "";
    expect(msg).toContain("Kimi Code API yanıtı JSON olarak ayrıştırılamadı");
    expect(msg).not.toContain(mockCred.secret);
  });
});

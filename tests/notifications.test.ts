import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { AuthService } from "../src/core/auth/auth";
import { createServer } from "../src/server/app";
import { AlertEvaluator, NotificationDispatcher } from "../src/core/notifier";
import type { AlertEvent, UsageReport } from "../src/types";

describe("Quota Notifications & Alert System", () => {
  it("dispatches notifications to ntfy, telegram, discord, and generic webhooks with correct payload", async () => {
    const interceptedRequests: Array<{ url: string; method: string; headers: Record<string, string>; body: any }> = [];

    const mockFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === "string" ? url : url.toString();
      const headers: Record<string, string> = {};
      if (init?.headers) {
        if (init.headers instanceof Headers) {
          init.headers.forEach((v, k) => {
            headers[k] = v;
          });
        } else if (Array.isArray(init.headers)) {
          init.headers.forEach(([k, v]) => {
            headers[k] = v;
          });
        } else {
          Object.assign(headers, init.headers);
        }
      }
      let body: any = init?.body;
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch {
          // plain string
        }
      }
      interceptedRequests.push({ url: urlStr, method: init?.method || "GET", headers, body });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as unknown as typeof fetch;

    const dispatcher = new NotificationDispatcher({ fetch: mockFetch });

    const baseEvent: AlertEvent = {
      userId: "u1",
      provider: "openai-codex",
      accountLabel: "Work ChatGPT",
      metric: "5-Hour Rolling Quota",
      metricId: "5h_quota",
      currentValue: 0.95,
      currentValueFormatted: "%95",
      threshold: 0.8,
      thresholdFormatted: "%80",
      type: "warning",
      timestamp: Date.now(),
    };

    // 1. ntfy dispatch
    const ntfyRes = await dispatcher.dispatch(
      { channel: "ntfy", url: "https://ntfy.sh/test-topic", token: "secret-tk" },
      baseEvent,
    );
    expect(ntfyRes.success).toBe(true);
    expect(interceptedRequests.length).toBe(1);
    expect(interceptedRequests[0].url).toBe("https://ntfy.sh/test-topic");
    expect(interceptedRequests[0].headers["Title"]).toContain("[useMeter] KOTA UYARISI");
    expect(interceptedRequests[0].headers["Authorization"]).toBe("Bearer secret-tk");
    expect(interceptedRequests[0].body).toContain("Work ChatGPT");

    // 2. telegram dispatch
    const tgRes = await dispatcher.dispatch(
      { channel: "telegram", botToken: "123456:BOT_TOKEN", chatId: "987654321" },
      { ...baseEvent, type: "exhausted", currentValue: 1.0, currentValueFormatted: "%100" },
    );
    expect(tgRes.success).toBe(true);
    expect(interceptedRequests.length).toBe(2);
    expect(interceptedRequests[1].url).toBe("https://api.telegram.org/bot123456:BOT_TOKEN/sendMessage");
    expect(interceptedRequests[1].body.chat_id).toBe("987654321");
    expect(interceptedRequests[1].body.text).toContain("KOTA TÜKENDİ");

    // 3. discord dispatch
    const discordRes = await dispatcher.dispatch(
      { channel: "discord", url: "https://discord.com/api/webhooks/123/abc" },
      { ...baseEvent, type: "recovered", currentValue: 0.0, currentValueFormatted: "%0" },
    );
    expect(discordRes.success).toBe(true);
    expect(interceptedRequests.length).toBe(3);
    expect(interceptedRequests[2].url).toBe("https://discord.com/api/webhooks/123/abc");
    expect(interceptedRequests[2].body.embeds[0].title).toContain("KOTA SIFIRLANDI");
    expect(interceptedRequests[2].body.embeds[0].color).toBe(0x10b981); // green

    // 4. webhook dispatch
    const webhookRes = await dispatcher.dispatch(
      { channel: "webhook", url: "https://my-hook.example.com/alerts" },
      baseEvent,
    );
    expect(webhookRes.success).toBe(true);
    expect(interceptedRequests.length).toBe(4);
    expect(interceptedRequests[3].url).toBe("https://my-hook.example.com/alerts");
    expect(interceptedRequests[3].body.event).toBe("quota_alert");
    expect(interceptedRequests[3].body.alert.provider).toBe("openai-codex");
  });

  it("evaluates quota thresholds, handles state transitions, and detects resets", async () => {
    const vault = new StorageVault(":memory:");
    const dispatcher = new NotificationDispatcher({
      fetch: (async () => {
        return new Response("ok", { status: 200 });
      }) as unknown as typeof fetch,
    });

    let mockClock = 1_000_000;
    const evaluator = new AlertEvaluator(vault, dispatcher, {
      now: () => mockClock,
      cooldownMs: 3600_000, // 1 hour
    });

    // Register user & credential
    const user = vault.createUser("alerts@example.com", "hash");
    const cred = vault.saveCredential(user.id, {
      provider: "openai-codex",
      accountLabel: "Primary Account",
      credentialType: "api_key",
      secret: "secret-123",
    });

    // Configure notifications
    vault.saveNotificationConfig(user.id, {
      enabled: true,
      channel: "ntfy",
      config: { channel: "ntfy", url: "https://ntfy.sh/alerts-test" },
      warningThresholdPercent: 80,
      notifyOnWarning: true,
      notifyOnExhausted: true,
      notifyOnReset: true,
    });

    const createReport = (usedFraction: number, status: "ok" | "warning" | "exhausted"): UsageReport => ({
      ownerId: user.id,
      credentialId: cred.id,
      provider: "openai-codex",
      accountLabel: "Primary Account",
      fetchedAt: mockClock,
      health: "healthy",
      limits: [
        {
          id: "5h_quota",
          label: "5-Hour Rolling Limit",
          amount: { usedFraction, unit: "percent" },
          status,
          window: { id: "5h", label: "5 Hours", resetLabel: "resets in 45m" },
        },
      ],
    });

    // 1. Initial normal usage (40%) -> No alert
    const r1 = await evaluator.evaluateReport(createReport(0.4, "ok"));
    expect(r1.length).toBe(0);

    // 2. Usage reaches 85% -> Warning alert emitted!
    mockClock += 60_000;
    const r2 = await evaluator.evaluateReport(createReport(0.85, "warning"));
    expect(r2.length).toBe(1);
    expect(r2[0].type).toBe("warning");
    expect(r2[0].currentValueFormatted).toBe("%85");

    // 3. Usage stays at 88% after 5 minutes -> Deduplication suppresses duplicate alert
    mockClock += 5 * 60_000;
    const r3 = await evaluator.evaluateReport(createReport(0.88, "warning"));
    expect(r3.length).toBe(0); // suppressed!

    // 4. Usage reaches 100% -> Exhausted alert emitted!
    mockClock += 5 * 60_000;
    const r4 = await evaluator.evaluateReport(createReport(1.0, "exhausted"));
    expect(r4.length).toBe(1);
    expect(r4[0].type).toBe("exhausted");

    // 5. Still 100% after 5 minutes -> Suppressed!
    mockClock += 5 * 60_000;
    const r5 = await evaluator.evaluateReport(createReport(1.0, "exhausted"));
    expect(r5.length).toBe(0);

    // 6. 5-hour window resets / regens back to 0% -> Recovery / Reset alert emitted!
    mockClock += 5 * 60_000;
    const r6 = await evaluator.evaluateReport(createReport(0.0, "ok"));
    expect(r6.length).toBe(1);
    expect(r6[0].type).toBe("recovered");
    expect(r6[0].metric).toBe("5-Hour Rolling Limit");

    vault.close();
  });

  it("handles notification settings API, secret masking, and test notification route", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const auth = new AuthService(vault);

    let testDispatched = false;
    const mockDispatcher = new NotificationDispatcher({
      fetch: (async () => {
        testDispatched = true;
        return new Response("ok", { status: 200 });
      }) as unknown as typeof fetch,
    });

    const app = createServer(vault, poller, registry, auth, {
      notificationDispatcher: mockDispatcher,
    });

    // Register User
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "notif-user@example.com", password: "Password-12345678!" }),
    });
    const cookie = regRes.headers.get("Set-Cookie")!;

    // 1. Initial config should be disabled with defaults
    const getInit = await app.request("/api/notifications/config", {
      headers: { Cookie: cookie },
    });
    expect(getInit.status).toBe(200);
    const initJson = (await getInit.json()) as { success: boolean; config: { enabled: boolean; channel: string } };
    expect(initJson.success).toBe(true);
    expect(initJson.config.enabled).toBe(false);

    // 2. Save Telegram configuration
    const saveTg = await app.request("/api/notifications/config", {
      method: "PUT",
      headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: true,
        channel: "telegram",
        config: {
          channel: "telegram",
          botToken: "123456789:ABCdefGHIjklMNO",
          chatId: "987654321",
        },
        warningThresholdPercent: 85,
        notifyOnWarning: true,
        notifyOnExhausted: true,
        notifyOnReset: true,
      }),
    });
    expect(saveTg.status).toBe(200);
    const saveTgJson = (await saveTg.json()) as { success: boolean; config: any };
    expect(saveTgJson.success).toBe(true);
    expect(saveTgJson.config.enabled).toBe(true);
    expect(saveTgJson.config.channel).toBe("telegram");
    expect(saveTgJson.config.config.chatId).toBe("987654321");
    // Secrets must NOT be returned in plaintext in the config view
    expect(saveTgJson.config.config.botToken).toBeUndefined();
    expect(saveTgJson.config.config.hasBotToken).toBe(true);

    // 3. Update without re-sending botToken (preserve existing secret)
    const updatePreserve = await app.request("/api/notifications/config", {
      method: "PUT",
      headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: true,
        channel: "telegram",
        config: {
          channel: "telegram",
          botToken: "", // empty -> should preserve existing!
          chatId: "987654321",
        },
        warningThresholdPercent: 90,
      }),
    });
    expect(updatePreserve.status).toBe(200);
    const userObj = vault.getUserByEmail("notif-user@example.com")!;
    const savedInDb = vault.getNotificationConfig(userObj.id)!;
    expect(savedInDb.config.channel).toBe("telegram");
    if (savedInDb.config.channel === "telegram") {
      expect(savedInDb.config.botToken).toBe("123456789:ABCdefGHIjklMNO");
    }

    // 4. Send test notification via POST /api/notifications/test
    testDispatched = false;
    const testRes = await app.request("/api/notifications/test", {
      method: "POST",
      headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(testRes.status).toBe(200);
    expect(testDispatched).toBe(true);

    // 5. Unauthenticated request rejected
    const unauthRes = await app.request("/api/notifications/config");
    expect(unauthRes.status).toBe(401);

    vault.close();
  });
});

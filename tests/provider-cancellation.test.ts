import { describe, expect, it } from "bun:test";
import { CodexAdapter } from "../src/core/providers/codex";
import { CursorAdapter } from "../src/core/providers/cursor";
import { GoogleAntigravityAdapter } from "../src/core/providers/google-antigravity";
import { GoogleGeminiCliAdapter } from "../src/core/providers/google-gemini-cli";
import { OpenRouterAdapter } from "../src/core/providers/openrouter";
import type { StoredCredential } from "../src/types";

const oauthCredential = (provider: string, options: Partial<StoredCredential> = {}): StoredCredential => ({
  id: `cancel-${provider}`,
  ownerId: "cancel-test-owner",
  provider,
  accountLabel: "Test account",
  credentialType: "oauth",
  secret: "test-access-token",
  createdAt: 1,
  updatedAt: 1,
  ...options,
});

const fetchFixture = (fn: (input: string | URL | Request, init?: RequestInit) => Promise<Response>): typeof fetch =>
  fn as unknown as typeof fetch;

describe("provider cancellation boundaries", () => {
  it("Gemini CLI rejects an aborted project lookup without dispatching quota lookup", async () => {
    const controller = new AbortController();
    const calls: string[] = [];
    const adapter = new GoogleGeminiCliAdapter();
    const fetch = fetchFixture(async (input) => {
      calls.push(input.toString());
      controller.abort(new Error("lookup cancelled"));
      controller.signal.throwIfAborted();
      throw new Error("synthetic request failure");
    });

    await expect(adapter.fetchUsage(oauthCredential("google-gemini-cli", { metadata: { projectId: "fixture-project" } }), {
      fetch,
      signal: controller.signal,
    })).rejects.toThrow("lookup cancelled");
    expect(calls).toEqual(["https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"]);
  });

  it("Gemini CLI preserves best-effort lookup failures when not aborted", async () => {
    const calls: string[] = [];
    const adapter = new GoogleGeminiCliAdapter();
    const fetch = fetchFixture(async (input) => {
      calls.push(input.toString());
      if (calls.length === 1) throw new Error("optional lookup unavailable");
      return Response.json({ buckets: [{ modelId: "fixture", remainingFraction: 0.75 }] });
    });

    const report = await adapter.fetchUsage(oauthCredential("google-gemini-cli", { metadata: { projectId: "fixture-project" } }), { fetch });
    expect(calls).toEqual([
      "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
      "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota",
    ]);
    expect(report.limits).toHaveLength(1);
  });

  it("Cursor rejects an aborted optional identity lookup without dispatching usage", async () => {
    const controller = new AbortController();
    const calls: string[] = [];
    const sub = Buffer.from(JSON.stringify({ sub: "auth0|fixture-user" })).toString("base64url");
    const secret = `header.${sub}.signature`;
    const adapter = new CursorAdapter();
    const fetch = fetchFixture(async (input) => {
      calls.push(input.toString());
      controller.abort(new Error("identity lookup cancelled"));
      controller.signal.throwIfAborted();
      throw new Error("synthetic request failure");
    });

    await expect(adapter.fetchUsage(oauthCredential("cursor", { secret, accountLabel: "Cursor" }), {
      fetch,
      signal: controller.signal,
    })).rejects.toThrow("identity lookup cancelled");
    expect(calls).toEqual(["https://cursor.com/api/auth/me"]);
  });

  it("Codex rejects an aborted optional reset-credit lookup instead of returning primary usage", async () => {
    const controller = new AbortController();
    const calls: string[] = [];
    const adapter = new CodexAdapter();
    const fetch = fetchFixture(async (input) => {
      const url = input.toString();
      calls.push(url);
      if (url.endsWith("/usage")) {
        return Response.json({ rate_limit: { primary_window: { used_percent: 20 } } });
      }
      controller.abort(new Error("reset credits cancelled"));
      controller.signal.throwIfAborted();
      throw new Error("synthetic request failure");
    });

    await expect(adapter.fetchUsage(oauthCredential("openai-codex", { credentialType: "api_key" }), {
      fetch,
      signal: controller.signal,
    })).rejects.toThrow("reset credits cancelled");
    expect(calls).toEqual([
      "https://chatgpt.com/backend-api/wham/usage",
      "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits",
    ]);
  });

  it("Codex retains primary usage after an ordinary reset-credit failure", async () => {
    const adapter = new CodexAdapter();
    const fetch = fetchFixture(async (input) => {
      if (input.toString().endsWith("/usage")) {
        return Response.json({ rate_limit: { primary_window: { used_percent: 20 } } });
      }
      throw new Error("optional reset-credit service unavailable");
    });

    const report = await adapter.fetchUsage(oauthCredential("openai-codex", { credentialType: "api_key" }), { fetch });
    expect(report.limits.map(limit => limit.id)).toEqual(["primary_window"]);
  });

  it("OpenRouter rejects an aborted optional credits lookup instead of returning key usage", async () => {
    const controller = new AbortController();
    const calls: string[] = [];
    const adapter = new OpenRouterAdapter();
    const fetch = fetchFixture(async (input) => {
      const url = input.toString();
      calls.push(url);
      if (url.endsWith("/auth/key")) return Response.json({ data: { usage: 3, limit: 10, limit_remaining: 7 } });
      controller.abort(new Error("credits lookup cancelled"));
      controller.signal.throwIfAborted();
      throw new Error("synthetic request failure");
    });

    await expect(adapter.fetchUsage(oauthCredential("openrouter", { credentialType: "api_key" }), {
      fetch,
      signal: controller.signal,
    })).rejects.toThrow("credits lookup cancelled");
    expect(calls).toEqual([
      "https://openrouter.ai/api/v1/auth/key",
      "https://openrouter.ai/api/v1/credits",
    ]);
  });

  it("OpenRouter retains key usage after an ordinary credits failure", async () => {
    const adapter = new OpenRouterAdapter();
    const fetch = fetchFixture(async (input) => {
      if (input.toString().endsWith("/auth/key")) return Response.json({ data: { usage: 3, limit: 10, limit_remaining: 7 } });
      throw new Error("optional credits service unavailable");
    });

    const report = await adapter.fetchUsage(oauthCredential("openrouter", { credentialType: "api_key" }), { fetch });
    expect(report.limits.map(limit => limit.id)).toEqual(["key_usage"]);
  });

  it("Antigravity aborts an active ECONNRESET backoff without retrying", async () => {
    const controller = new AbortController();
    const quotaFailureObserved = Promise.withResolvers<void>();
    const calls: string[] = [];
    const adapter = new GoogleAntigravityAdapter();
    const fetch = fetchFixture(async (input) => {
      const url = input.toString();
      calls.push(url);
      if (url.endsWith("loadCodeAssist")) return Response.json({ cloudaicompanionProject: "fixture-project" });
      quotaFailureObserved.resolve();
      const error = new Error("ECONNRESET");
      Object.assign(error, { code: "ECONNRESET" });
      throw error;
    });

    const startedAt = performance.now();
    const pending = adapter.fetchUsage(oauthCredential("antigravity", {
      credentialType: "api_key",
      metadata: { projectId: "fixture-project" },
    }), { fetch, signal: controller.signal });
    try {
      await quotaFailureObserved.promise;
      // Let the adapter enter its real 500 ms Node timer before aborting it.
      await new Promise<void>(resolve => setTimeout(resolve, 0));
      controller.abort(new Error("backoff cancelled"));
      await expect(pending).rejects.toThrow();
      expect(performance.now() - startedAt).toBeLessThan(400);
      expect(calls).toEqual([
        "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
        "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
      ]);
    } finally {
      controller.abort();
      await pending.catch(() => undefined);
    }
  });
});

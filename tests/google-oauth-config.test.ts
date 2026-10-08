import { describe, expect, it } from "bun:test";
import {
  getGoogleOAuthConfig,
  getGoogleRedirectUri,
  initiateGoogleAuth,
  exchangeGoogleCode,
  validateGoogleOAuthConfig,
  isLoopbackRedirectUri,
} from "../src/core/oauth/google";
import { GoogleAntigravityAdapter } from "../src/core/providers/google-antigravity";

describe("Google OAuth configuration and validation", () => {
  const originalClientId = process.env["GOOGLE_OAUTH_CLIENT_ID"];
  const originalClientSecret = process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
  const originalRedirectUri = process.env["GOOGLE_OAUTH_REDIRECT_URI"];
  const originalNodeEnv = process.env["NODE_ENV"];

  function restoreEnv() {
    if (originalClientId !== undefined) {
      process.env["GOOGLE_OAUTH_CLIENT_ID"] = originalClientId;
    } else {
      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
    }
    if (originalClientSecret !== undefined) {
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = originalClientSecret;
    } else {
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
    }
    if (originalRedirectUri !== undefined) {
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = originalRedirectUri;
    } else {
      delete process.env["GOOGLE_OAUTH_REDIRECT_URI"];
    }
    if (originalNodeEnv !== undefined) {
      process.env["NODE_ENV"] = originalNodeEnv;
    } else {
      delete process.env["NODE_ENV"];
    }
  }

  it("identifies loopback redirect URIs correctly", () => {
    expect(isLoopbackRedirectUri("http://127.0.0.1:51121/oauth-callback")).toBe(true);
    expect(isLoopbackRedirectUri("http://localhost:3100/callback")).toBe(true);
    expect(isLoopbackRedirectUri("https://usemeter.example.com/api/oauth/google/callback")).toBe(false);
    expect(isLoopbackRedirectUri("http://example.com/oauth")).toBe(false);
    expect(isLoopbackRedirectUri("not-a-valid-url")).toBe(false);
  });

  it("permits local loopback redirect URI with default legacy client", () => {
    try {
      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
      delete process.env["GOOGLE_OAUTH_REDIRECT_URI"];

      const config = validateGoogleOAuthConfig();
      expect(config.redirectUri).toBe("http://127.0.0.1:51121/oauth-callback");
      expect(config.isCustomClient).toBe(false);

      const init = initiateGoogleAuth();
      expect(init.authUrl).toContain("accounts.google.com");
      expect(init.authUrl).toContain(encodeURIComponent("http://127.0.0.1:51121/oauth-callback"));
      expect(init.verifier).toBeDefined();
      expect(init.state).toBeDefined();
    } finally {
      restoreEnv();
    }
  });

  it("preserves a custom loopback redirect for local development", () => {
    try {
      process.env["NODE_ENV"] = "test";
      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "http://localhost:51121/oauth-callback";

      expect(validateGoogleOAuthConfig().redirectUri).toBe("http://localhost:51121/oauth-callback");
    } finally {
      restoreEnv();
    }
  });

  it("rejects a public redirect without custom credentials outside production", () => {
    try {
      process.env["NODE_ENV"] = "test";
      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";

      expect(() => validateGoogleOAuthConfig()).toThrow(
        /Public Google OAuth redirect URI requires custom GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET/,
      );
    } finally {
      restoreEnv();
    }
  });

  it("fails early when only client ID or only client secret is provided", () => {
    try {
      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "custom-client-id.apps.googleusercontent.com";
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";

      expect(() => validateGoogleOAuthConfig()).toThrow(/must both be provided together/);

      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "custom-client-secret";
      expect(() => validateGoogleOAuthConfig()).toThrow(/must both be provided together/);
    } finally {
      restoreEnv();
    }
  });
  it("requires an exact HTTPS callback and rejects query, fragment, or user information", () => {
    const validCredentials = {
      clientId: "operator-client-id.apps.googleusercontent.com",
      clientSecret: "operator-client-secret",
    };
    const invalidRedirects = [
      "http://usemeter.example.com/api/oauth/google/callback",
      "https://usemeter.example.com/api/oauth/google/callback/extra",
      "https://usemeter.example.com/api/oauth/google/../google/callback",
      "https://usemeter.example.com/api/oauth/google/callback?state=unexpected",
      "https://usemeter.example.com/api/oauth/google/callback?",
      "https://usemeter.example.com/api/oauth/google/callback#fragment",
      "https://usemeter.example.com/api/oauth/google/callback#",
      "https://user:password@usemeter.example.com/api/oauth/google/callback",
      "https://@usemeter.example.com/api/oauth/google/callback",
    ];

    for (const redirectUri of invalidRedirects) {
      expect(() => validateGoogleOAuthConfig({ ...validCredentials, redirectUri })).toThrow(
        /Invalid Google OAuth redirect URI/,
      );
    }

    expect(() =>
      validateGoogleOAuthConfig({
        ...validCredentials,
        redirectUri: "https://usemeter.example.com/api/oauth/google/callback",
      }),
    ).not.toThrow();
  });

  it("rejects embedded default client credentials for public callbacks", () => {
    try {
      delete process.env["GOOGLE_OAUTH_CLIENT_ID"];
      delete process.env["GOOGLE_OAUTH_CLIENT_SECRET"];
      delete process.env["GOOGLE_OAUTH_REDIRECT_URI"];
      const embeddedClient = getGoogleOAuthConfig();
      const redirectUri = "https://usemeter.example.com/api/oauth/google/callback";

      expect(() =>
        validateGoogleOAuthConfig({
          clientId: embeddedClient.clientId,
          clientSecret: "operator-client-secret",
          redirectUri,
        }),
      ).toThrow(/Public Google OAuth redirect URI requires custom/);
      expect(() =>
        validateGoogleOAuthConfig({
          clientId: "operator-client-id.apps.googleusercontent.com",
          clientSecret: embeddedClient.clientSecret,
          redirectUri,
        }),
      ).toThrow(/Public Google OAuth redirect URI requires custom/);
    } finally {
      restoreEnv();
    }
  });

  it("uses embedded loopback/manual OAuth in production when only the legacy public redirect is configured", async () => {
    const originalFetch = globalThis.fetch;
    let refreshBody = "";
    const mockFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url instanceof Request ? url.url : url.toString();
      if (urlStr !== "https://oauth2.googleapis.com/token") {
        throw new Error(`Unexpected synthetic Google OAuth URL: ${urlStr}`);
      }
      refreshBody = init?.body?.toString() ?? "";
      return new Response(JSON.stringify({ access_token: "mock-renewed-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof fetch;

    try {
      process.env["NODE_ENV"] = "production";
      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "";
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";

      const config = validateGoogleOAuthConfig();
      expect(config.redirectUri).toBe("http://127.0.0.1:51121/oauth-callback");
      expect(config.isCustomClient).toBe(false);
      expect(getGoogleRedirectUri()).toBe(config.redirectUri);

      const init = initiateGoogleAuth();
      expect(new URL(init.authUrl).searchParams.get("redirect_uri")).toBe(config.redirectUri);
      await expect(
        new GoogleAntigravityAdapter().refreshAccessToken("mock-refresh-token", mockFetch),
      ).resolves.toBe("mock-renewed-token");

      const refreshParams = new URLSearchParams(refreshBody);
      expect(refreshParams.get("client_id")).toBe(config.clientId);
      expect(refreshParams.get("client_secret")).toBe(config.clientSecret);
      expect(refreshParams.get("refresh_token")).toBe("mock-refresh-token");
      expect(refreshParams.get("grant_type")).toBe("refresh_token");
      expect(refreshParams.has("redirect_uri")).toBe(false);

      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "custom-client-id.apps.googleusercontent.com";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "custom-client-secret";
      delete process.env["GOOGLE_OAUTH_REDIRECT_URI"];
      expect(() => validateGoogleOAuthConfig()).toThrow(
        /GOOGLE_OAUTH_REDIRECT_URI must be explicitly configured/,
      );
    } finally {
      globalThis.fetch = originalFetch;
      restoreEnv();
    }
  });

  it("accepts operator-owned client credentials with public redirect URI", () => {
    try {
      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "custom-operator-client-id.apps.googleusercontent.com";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "custom-operator-secret";
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";

      const config = validateGoogleOAuthConfig();
      expect(config.clientId).toBe("custom-operator-client-id.apps.googleusercontent.com");
      expect(config.clientSecret).toBe("custom-operator-secret");
      expect(config.redirectUri).toBe("https://usemeter.example.com/api/oauth/google/callback");
      expect(config.isCustomClient).toBe(true);

      const init = initiateGoogleAuth();
      expect(init.authUrl).toContain("custom-operator-client-id.apps.googleusercontent.com");
      expect(init.authUrl).toContain(encodeURIComponent("https://usemeter.example.com/api/oauth/google/callback"));
      // Must never leak secret in auth URL
      expect(init.authUrl).not.toContain("custom-operator-secret");
      expect(getGoogleRedirectUri()).toBe("https://usemeter.example.com/api/oauth/google/callback");
    } finally {
      restoreEnv();
    }
  });

  it("supports config injection/overrides directly without env mutation", () => {
    const overrides = {
      clientId: "injected-client-id.apps.googleusercontent.com",
      clientSecret: "injected-secret",
      redirectUri: "https://usemeter.example.com/api/oauth/google/callback",
    };

    const config = validateGoogleOAuthConfig(overrides);
    expect(config.clientId).toBe("injected-client-id.apps.googleusercontent.com");

    const init = initiateGoogleAuth(overrides);
    expect(init.authUrl).toContain("injected-client-id.apps.googleusercontent.com");
    expect(init.authUrl).not.toContain("injected-secret");
  });

  it("uses matching client ID, secret, and redirect URI during code exchange", async () => {
    const originalFetch = globalThis.fetch;
    let interceptedBody: string | undefined;

    const mockFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url instanceof Request ? url.url : url.toString();
      if (urlStr === "https://oauth2.googleapis.com/token") {
        interceptedBody = init?.body?.toString();
        return new Response(
          JSON.stringify({
            access_token: "mock-google-token",
            refresh_token: "mock-google-refresh",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (urlStr === "https://www.googleapis.com/oauth2/v1/userinfo?alt=json") {
        return new Response(
          JSON.stringify({ email: "operator@example.com" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`Unexpected Google OAuth mock URL: ${urlStr}`);
    }) as unknown as typeof fetch;

    globalThis.fetch = mockFetch;
    try {
      const overrides = {
        clientId: "matching-client-id.apps.googleusercontent.com",
        clientSecret: "matching-secret-value",
        redirectUri: "https://usemeter.example.com/api/oauth/google/callback",
      };

      const result = await exchangeGoogleCode("test-code", "test-verifier", overrides);
      expect(result.accessToken).toBe("mock-google-token");
      expect(result.email).toBe("operator@example.com");

      expect(interceptedBody).toBeDefined();
      const params = new URLSearchParams(interceptedBody);
      expect(params.get("client_id")).toBe("matching-client-id.apps.googleusercontent.com");
      expect(params.get("client_secret")).toBe("matching-secret-value");
      expect(params.get("redirect_uri")).toBe("https://usemeter.example.com/api/oauth/google/callback");
      expect(params.get("code")).toBe("test-code");
      expect(params.get("code_verifier")).toBe("test-verifier");
      expect(params.get("grant_type")).toBe("authorization_code");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("uses the same configured web client for first login and token renewal", async () => {
    const originalFetch = globalThis.fetch;
    const tokenRequestBodies: string[] = [];
    const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url === "https://oauth2.googleapis.com/token") {
        const body = init?.body?.toString() ?? "";
        tokenRequestBodies.push(body);
        const params = new URLSearchParams(body);
        if (params.get("grant_type") === "authorization_code") {
          return new Response(
            JSON.stringify({
              access_token: "mock-google-access-token",
              refresh_token: "mock-google-refresh-token",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (params.get("grant_type") === "refresh_token") {
          return new Response(
            JSON.stringify({ access_token: "mock-google-renewed-token" }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`Unexpected Google token grant type: ${params.get("grant_type")}`);
      }
      if (url === "https://www.googleapis.com/oauth2/v1/userinfo?alt=json") {
        return new Response(
          JSON.stringify({ email: "operator@example.com" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`Unexpected Google OAuth mock URL: ${url}`);
    }) as unknown as typeof fetch;

    try {
      process.env["GOOGLE_OAUTH_CLIENT_ID"] = "matching-client-id.apps.googleusercontent.com";
      process.env["GOOGLE_OAUTH_CLIENT_SECRET"] = "matching-client-secret";
      process.env["GOOGLE_OAUTH_REDIRECT_URI"] = "https://usemeter.example.com/api/oauth/google/callback";
      globalThis.fetch = mockFetch;

      const auth = initiateGoogleAuth();
      expect(auth.authUrl).toContain("matching-client-id.apps.googleusercontent.com");
      const firstLogin = await exchangeGoogleCode("mock-authorization-code", auth.verifier);
      expect(firstLogin.accessToken).toBe("mock-google-access-token");
      expect(firstLogin.refreshToken).toBe("mock-google-refresh-token");
      expect(firstLogin.email).toBe("operator@example.com");

      const renewedToken = await new GoogleAntigravityAdapter().refreshAccessToken(
        firstLogin.refreshToken!,
        mockFetch,
      );
      expect(renewedToken).toBe("mock-google-renewed-token");

      const loginParams = new URLSearchParams(tokenRequestBodies[0]);
      expect(loginParams.get("client_id")).toBe("matching-client-id.apps.googleusercontent.com");
      expect(loginParams.get("client_secret")).toBe("matching-client-secret");
      expect(loginParams.get("redirect_uri")).toBe("https://usemeter.example.com/api/oauth/google/callback");
      expect(loginParams.get("grant_type")).toBe("authorization_code");

      const refreshParams = new URLSearchParams(tokenRequestBodies[1]);
      expect(refreshParams.get("client_id")).toBe("matching-client-id.apps.googleusercontent.com");
      expect(refreshParams.get("client_secret")).toBe("matching-client-secret");
      expect(refreshParams.get("refresh_token")).toBe("mock-google-refresh-token");
      expect(refreshParams.get("grant_type")).toBe("refresh_token");
    } finally {
      globalThis.fetch = originalFetch;
      restoreEnv();
    }
  });
});

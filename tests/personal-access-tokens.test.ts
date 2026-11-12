import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { AuthService } from "../src/core/auth/auth";
import { createServer } from "../src/server/app";
import { hashPersonalAccessToken } from "../src/core/crypto";
import type { UsageReport } from "../src/types";

describe("Personal Access Tokens (PAT) & V1 API", () => {
  it("manages PAT lifecycle in StorageVault and AuthService", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    // Register user
    const regRes = await auth.register("pat-user@example.com", "Password-12345678!");
    expect(regRes.success).toBe(true);
    if (!regRes.success) throw new Error("Registration failed");
    const userId = regRes.data.user.id;

    // 1. Create token via AuthService
    const createResult = await auth.createPersonalAccessToken(userId, "Waybar Widget", 30);
    expect(createResult.success).toBe(true);
    if (!createResult.success) throw new Error("Token creation failed");

    const { token, rawToken } = createResult.data;
    expect(rawToken.startsWith("um_pat_")).toBe(true);
    expect(token.name).toBe("Waybar Widget");
    expect(token.tokenPrefix).toContain("um_pat_");
    expect(token.tokenPrefix).toContain("...");
    expect(token.lastUsedAt).toBeNull();
    expect(token.expiresAt).toBeGreaterThan(Date.now());

    // 2. List tokens
    const listResult = await auth.listPersonalAccessTokens(userId);
    expect(listResult.success).toBe(true);
    if (!listResult.success) throw new Error("List failed");
    expect(listResult.data.length).toBe(1);
    expect(listResult.data[0].id).toBe(token.id);
    expect(listResult.data[0].name).toBe("Waybar Widget");
    const item0 = listResult.data[0] as unknown as Record<string, unknown>;
    expect(item0["rawToken"]).toBeUndefined();
    expect(item0["tokenHash"]).toBeUndefined();

    // 3. Authenticate with raw token
    const authSuccess = await auth.authenticateBearerToken(rawToken);
    expect(authSuccess.success).toBe(true);
    if (!authSuccess.success) throw new Error("Auth failed");
    expect(authSuccess.data.user.id).toBe(userId);
    expect(authSuccess.data.user.email).toBe("pat-user@example.com");
    expect(authSuccess.data.token.id).toBe(token.id);

    // 4. Authenticate with invalid/tampered token
    const authInvalid = await auth.authenticateBearerToken("um_pat_invaliddeadbeef12345678");
    expect(authInvalid.success).toBe(false);

    // 5. Expired token rejection
    const expiredTokenRes = await auth.createPersonalAccessToken(userId, "Short Lived", 0.00001);
    expect(expiredTokenRes.success).toBe(true);
    if (!expiredTokenRes.success) throw new Error("Expired token creation failed");
    // Manually backdate expiration in vault
    const hash = hashPersonalAccessToken(expiredTokenRes.data.rawToken);
    const backdated = vault.getPersonalAccessTokenByHash(hash, Date.now() + 100_000);
    expect(backdated).toBeNull();

    // 6. Revoke token
    const revokeResult = await auth.revokePersonalAccessToken(userId, token.id);
    expect(revokeResult.success).toBe(true);

    const authAfterRevoke = await auth.authenticateBearerToken(rawToken);
    expect(authAfterRevoke.success).toBe(false);

    // 7. Token limit enforcement (max 25)
    // Currently 1 active token ("Short Lived") exists. Create 24 more to reach exactly 25.
    for (let i = 0; i < 24; i++) {
      const res = await auth.createPersonalAccessToken(userId, `Token ${i}`);
      expect(res.success).toBe(true);
    }
    const overflowRes = await auth.createPersonalAccessToken(userId, "Token Overflow");
    expect(overflowRes.success).toBe(false);
    if (!overflowRes.success) {
      expect(overflowRes.error).toBe("TOKEN_LIMIT_REACHED");
    }

    vault.close();
  });

  it("authenticates external API requests via Bearer token and isolates users", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const auth = new AuthService(vault);
    const app = createServer(vault, poller, registry, auth);

    // Register User 1
    const regUser1 = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user1@example.com", password: "Password-12345678!" }),
    });
    const cookie1 = regUser1.headers.get("Set-Cookie")!;

    // Register User 2
    const regUser2 = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user2@example.com", password: "Password-12345678!" }),
    });
    const cookie2 = regUser2.headers.get("Set-Cookie")!;

    // 1. Create token for User 1
    const createTokenRes = await app.request("/api/tokens", {
      method: "POST",
      headers: {
        Cookie: cookie1,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "CLI Access", expiresInDays: 90 }),
    });
    expect(createTokenRes.status).toBe(200);
    const tokenData = (await createTokenRes.json()) as {
      success: boolean;
      token: { id: string; name: string; tokenPrefix: string };
      rawToken: string;
    };
    expect(tokenData.success).toBe(true);
    expect(tokenData.rawToken.startsWith("um_pat_")).toBe(true);
    const pat1 = tokenData.rawToken;

    // 2. User 2 cannot see User 1's tokens
    const listTokensUser2 = await app.request("/api/tokens", {
      headers: { Cookie: cookie2 },
    });
    const listJson2 = (await listTokensUser2.json()) as { success: boolean; tokens: unknown[] };
    expect(listJson2.tokens.length).toBe(0);

    // 3. User 2 cannot delete User 1's token
    const deleteCross = await app.request(`/api/tokens/${tokenData.token.id}`, {
      method: "DELETE",
      headers: { Cookie: cookie2 },
    });
    expect(deleteCross.status).toBe(200);
    // User 1's token is still intact
    const listTokensUser1 = await app.request("/api/tokens", {
      headers: { Cookie: cookie1 },
    });
    const listJson1 = (await listTokensUser1.json()) as { success: boolean; tokens: unknown[] };
    expect(listJson1.tokens.length).toBe(1);

    // 4. Save a mock usage snapshot for User 1
    const user1Obj = vault.getUserByEmail("user1@example.com")!;
    const cred1 = vault.saveCredential(user1Obj.id, {
      provider: "openrouter",
      accountLabel: "User1 OpenRouter",
      credentialType: "api_key",
      secret: "sk-or-test-secret-1234567890",
    });

    const mockReport: UsageReport = {
      provider: "openrouter",
      credentialId: cred1.id,
      accountLabel: cred1.accountLabel,
      fetchedAt: Date.now(),
      health: "healthy",
      limits: [
        {
          id: "account_balance",
          label: "Account Net Balance",
          amount: { used: 0, remaining: 15.5, limit: 15.5, unit: "usd" },
          status: "ok",
        },
        {
          id: "key_usage",
          label: "API Key Spending",
          amount: { used: 4.25, unit: "usd" },
          status: "ok",
        },
      ],
    };
    vault.saveUsageSnapshot(user1Obj.id, mockReport);

    // 5. Query /api/v1/usage with PAT Bearer token
    const v1UsageRes = await app.request("/api/v1/usage", {
      headers: { Authorization: `Bearer ${pat1}` },
    });
    expect(v1UsageRes.status).toBe(200);
    const usageJson = (await v1UsageRes.json()) as {
      success: boolean;
      data: Array<{ provider: string; accountLabel: string; limits: unknown[] }>;
    };
    expect(usageJson.success).toBe(true);
    expect(usageJson.data.length).toBe(1);
    expect(usageJson.data[0].provider).toBe("openrouter");
    expect(usageJson.data[0].accountLabel).toBe("User1 OpenRouter");

    // 6. Query /api/v1/summary with PAT Bearer token
    const v1SummaryRes = await app.request("/api/v1/summary", {
      headers: { Authorization: `Bearer ${pat1}` },
    });
    expect(v1SummaryRes.status).toBe(200);
    const summaryJson = (await v1SummaryRes.json()) as {
      success: boolean;
      user: { email: string };
      totals: { totalBalanceUsd: number; totalSpentUsd: number; healthyCount: number };
      accounts: Array<{ provider: string; label?: string; accountLabel?: string; balanceUsd?: number }>;
    };
    expect(summaryJson.success).toBe(true);
    expect(summaryJson.user.email).toBe("user1@example.com");
    expect(summaryJson.totals.totalBalanceUsd).toBe(15.5);
    expect(summaryJson.totals.totalSpentUsd).toBe(4.25);
    expect(summaryJson.totals.healthyCount).toBe(1);
    expect(summaryJson.accounts[0].balanceUsd).toBe(15.5);

    // 7. Standard /api/data also accepts Bearer token
    const standardDataRes = await app.request("/api/data", {
      headers: { Authorization: `Bearer ${pat1}` },
    });
    expect(standardDataRes.status).toBe(200);
    const stdJson = (await standardDataRes.json()) as { success: boolean; data: unknown[] };
    expect(stdJson.success).toBe(true);
    expect(stdJson.data.length).toBe(1);

    // 8. Invalid Bearer token returns 401
    const invalidBearerRes = await app.request("/api/v1/usage", {
      headers: { Authorization: "Bearer um_pat_bogustoken12345" },
    });
    expect(invalidBearerRes.status).toBe(401);

    // 9. Missing auth returns 401
    const noAuthRes = await app.request("/api/v1/usage");
    expect(noAuthRes.status).toBe(401);

    // 10. User 1 revokes the token
    const deleteTokenRes = await app.request(`/api/tokens/${tokenData.token.id}`, {
      method: "DELETE",
      headers: { Cookie: cookie1 },
    });
    expect(deleteTokenRes.status).toBe(200);

    // 11. Now Bearer token returns 401
    const revokedRes = await app.request("/api/v1/usage", {
      headers: { Authorization: `Bearer ${pat1}` },
    });
    expect(revokedRes.status).toBe(401);

    vault.close();
  });
});

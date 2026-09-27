import { describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StorageVault } from "../src/core/storage/vault";
import { ProviderRegistry } from "../src/core/providers/registry";
import type { ProviderAdapter } from "../src/core/providers/adapter";
import { PollerEngine } from "../src/core/poller/poller";
import { AuthService } from "../src/core/auth/auth";
import { createServer } from "../src/server/app";
import type { StoredCredential, UsageReport } from "../src/types";

describe("API Credential and Usage Report Redaction", () => {
  it("never discloses refreshToken, secret, or report.raw on /api/data, /api/usage, and /api/poll while preserving presentation metadata and tenant isolation", async () => {
    const dbPath = join(tmpdir(), `test-redaction-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const vault = new StorageVault(dbPath);
    const rawDb = new Database(dbPath);
    const registry = new ProviderRegistry();

    try {
      // Register a synthetic provider adapter that returns raw data and sensitive debug dumps
      const mockKimiAdapter: ProviderAdapter = {
        id: "kimi-code",
        supports: (provider: string) => provider === "kimi-code",
        fetchUsage: async (credential: StoredCredential): Promise<UsageReport> => {
          return {
            ownerId: credential.ownerId,
            provider: credential.provider,
            credentialId: credential.id,
            accountLabel: credential.accountLabel,
            fetchedAt: 1720000000000,
            limits: [
              {
                id: "5h_limit",
                label: "5-Hour Quota",
                amount: { used: 15, limit: 100, remaining: 85, unit: "percent" },
                status: "ok",
              },
            ],
            raw: {
              sensitiveHeader: `Bearer ${credential.secret}`,
              internalKimiTokenDump: "kimi-raw-unredacted-upstream-token-9999",
              metaAccount: "kimi-internal-account-blob",
            },
          };
        },
      };
      registry.register(mockKimiAdapter);

      const poller = new PollerEngine(vault, registry);
      const auth = new AuthService(vault);
      const app = createServer(vault, poller, registry, auth);

      // 1. Create two isolated test users (Alice and Bob)
      const aliceReg = await auth.register("alice@example.com", "Password12345678!");
      if (!aliceReg.success) throw new Error("Alice registration failed");
      const alice = aliceReg.data.user;
      const aliceCookie = `usage_session=${encodeURIComponent(aliceReg.data.token)}`;

      const bobReg = await auth.register("bob@example.com", "Password12345678!");
      if (!bobReg.success) throw new Error("Bob registration failed");
      const bobCookie = `usage_session=${encodeURIComponent(bobReg.data.token)}`;

      // 2. Save Alice's credential containing sensitive tokens and allowable presentation metadata
      const aliceSecret = "sk-kimi-access-token-secret-11111";
      const aliceRefreshToken = "rt-kimi-refresh-token-secret-22222";
      const aliceCred = vault.saveCredential(alice.id, {
        provider: "kimi-code",
        accountLabel: "Alice Kimi Work",
        accent: "emerald",
        credentialType: "oauth",
        secret: aliceSecret,
        metadata: {
          refreshToken: aliceRefreshToken,
          email: "alice.work@moonshot.cn",
          login: "alice_kimi",
          username: "alice_k",
          accountId: "kimi-acc-777",
          userId: "kimi-user-888",
          planType: "pro",
          secretNotes: "confidential internal note",
          internalOAuthState: "oauth-state-secret-33333",
        },
      });

      // 3. Save a usage snapshot directly into the vault for Alice with an explicit report.raw
      const aliceReportWithRaw: UsageReport = {
        ownerId: alice.id,
        provider: "kimi-code",
        credentialId: aliceCred.id,
        accountLabel: "Alice Kimi Work",
        fetchedAt: 1720000000000,
        limits: [
          {
            id: "5h_limit",
            label: "5-Hour Quota",
            amount: { used: 15, limit: 100, remaining: 85, unit: "percent" },
            status: "ok",
          },
        ],
        raw: {
          leakCheckToken: "raw-report-leak-44444",
        },
      };
      vault.saveUsageSnapshot(alice.id, aliceReportWithRaw);

      // Force raw data into the SQLite snapshot row to verify backend/API sanitization
      rawDb.prepare(`
        UPDATE usage_snapshots
        SET report_json = ?
        WHERE credential_id = ?
      `).run(
        JSON.stringify({
          ...aliceReportWithRaw,
          raw: {
            embeddedRawToken: "raw-db-secret-55555",
          },
        }),
        aliceCred.id
      );

      // 4. Test GET /api/data for Alice
      const dataRes = await app.request("/api/data", {
        headers: { Cookie: aliceCookie },
      });
      expect(dataRes.status).toBe(200);
      const dataJsonText = await dataRes.text();
      const dataJson = JSON.parse(dataJsonText) as { success: boolean; data: Record<string, unknown>[] };

      expect(dataJson.success).toBe(true);
      expect(dataJson.data.length).toBe(1);
      const aliceReportData = dataJson.data[0]!;

      // Sensitive tokens and raw payloads MUST NOT be exposed
      expect(aliceReportData["secret"]).toBeUndefined();
      expect(aliceReportData["raw"]).toBeUndefined();
      expect(aliceReportData["ownerId"]).toBeUndefined();

      const dataMeta = aliceReportData["metadata"] as Record<string, unknown>;
      expect(dataMeta).toBeDefined();
      expect(dataMeta["refreshToken"]).toBeUndefined();
      expect(dataMeta["secretNotes"]).toBeUndefined();
      expect(dataMeta["internalOAuthState"]).toBeUndefined();

      // Presentation metadata MUST be preserved
      expect(dataMeta["email"]).toBe("alice.work@moonshot.cn");
      expect(dataMeta["login"]).toBe("alice_kimi");
      expect(dataMeta["username"]).toBe("alice_k");
      expect(dataMeta["accountId"]).toBe("kimi-acc-777");
      expect(dataMeta["userId"]).toBe("kimi-user-888");
      expect(dataMeta["planType"]).toBe("pro");

      // Display fields preserved
      expect(aliceReportData["accountLabel"]).toBe("Alice Kimi Work");
      expect(aliceReportData["accent"]).toBe("emerald");
      expect(aliceReportData["provider"]).toBe("kimi-code");
      expect(Array.isArray(aliceReportData["limits"])).toBe(true);

      // String scan of the full serialized response to ensure zero leakage
      expect(dataJsonText).not.toContain(aliceSecret);
      expect(dataJsonText).not.toContain(aliceRefreshToken);
      expect(dataJsonText).not.toContain("raw-db-secret-55555");
      expect(dataJsonText).not.toContain("confidential internal note");
      expect(dataJsonText).not.toContain("oauth-state-secret-33333");

      // 5. Test GET /api/usage for Alice
      const usageRes = await app.request("/api/usage", {
        headers: { Cookie: aliceCookie },
      });
      expect(usageRes.status).toBe(200);
      const usageJsonText = await usageRes.text();
      const usageJson = JSON.parse(usageJsonText) as { success: boolean; data: Record<string, unknown>[] };

      expect(usageJson.success).toBe(true);
      expect(usageJson.data.length).toBe(1);
      const aliceUsageData = usageJson.data[0]!;

      expect(aliceUsageData["secret"]).toBeUndefined();
      expect(aliceUsageData["raw"]).toBeUndefined();
      expect(aliceUsageData["ownerId"]).toBeUndefined();
      const usageMeta = aliceUsageData["metadata"] as Record<string, unknown>;
      expect(usageMeta["refreshToken"]).toBeUndefined();
      expect(usageMeta["email"]).toBe("alice.work@moonshot.cn");
      expect(usageJsonText).not.toContain(aliceSecret);
      expect(usageJsonText).not.toContain(aliceRefreshToken);
      expect(usageJsonText).not.toContain("raw-db-secret-55555");

      // 6. Test POST /api/poll for Alice (manual poll all credentials)
      const pollAllRes = await app.request("/api/poll", {
        method: "POST",
        headers: { Cookie: aliceCookie },
      });
      expect(pollAllRes.status).toBe(200);
      const pollAllJsonText = await pollAllRes.text();
      const pollAllJson = JSON.parse(pollAllJsonText) as {
        success: boolean;
        count: number;
        data: Record<string, unknown>[];
      };

      expect(pollAllJson.success).toBe(true);
      expect(pollAllJson.count).toBe(1);
      expect(pollAllJson.data.length).toBe(1);
      const polledReport = pollAllJson.data[0]!;

      expect(polledReport["raw"]).toBeUndefined();
      expect(polledReport["ownerId"]).toBeUndefined();
      expect(polledReport["secret"]).toBeUndefined();

      const polledMeta = polledReport["metadata"] as Record<string, unknown>;
      expect(polledMeta).toBeDefined();
      expect(polledMeta["refreshToken"]).toBeUndefined();
      expect(polledMeta["email"]).toBe("alice.work@moonshot.cn");
      expect(polledMeta["planType"]).toBe("pro");

      expect(pollAllJsonText).not.toContain(aliceSecret);
      expect(pollAllJsonText).not.toContain(aliceRefreshToken);
      expect(pollAllJsonText).not.toContain("kimi-raw-unredacted-upstream-token-9999");
      expect(pollAllJsonText).not.toContain("kimi-internal-account-blob");

      // 7. Test POST /api/credentials/:id/poll for Alice's single credential
      const pollSingleRes = await app.request(`/api/credentials/${aliceCred.id}/poll`, {
        method: "POST",
        headers: { Cookie: aliceCookie },
      });
      expect(pollSingleRes.status).toBe(200);
      const pollSingleJsonText = await pollSingleRes.text();
      const pollSingleJson = JSON.parse(pollSingleJsonText) as {
        success: boolean;
        data: Record<string, unknown>;
      };

      expect(pollSingleJson.success).toBe(true);
      const singleData = pollSingleJson.data;
      expect(singleData["raw"]).toBeUndefined();
      expect(singleData["ownerId"]).toBeUndefined();
      expect(singleData["secret"]).toBeUndefined();

      const singleMeta = singleData["metadata"] as Record<string, unknown>;
      expect(singleMeta).toBeDefined();
      expect(singleMeta["refreshToken"]).toBeUndefined();
      expect(singleMeta["email"]).toBe("alice.work@moonshot.cn");
      expect(pollSingleJsonText).not.toContain(aliceSecret);
      expect(pollSingleJsonText).not.toContain(aliceRefreshToken);
      expect(pollSingleJsonText).not.toContain("kimi-raw-unredacted-upstream-token-9999");

      // 8. Test Tenant Isolation: Bob CANNOT see or poll Alice's credentials or reports
      const bobDataRes = await app.request("/api/data", {
        headers: { Cookie: bobCookie },
      });
      expect(bobDataRes.status).toBe(200);
      const bobDataJson = (await bobDataRes.json()) as { success: boolean; data: unknown[] };
      expect(bobDataJson.success).toBe(true);
      expect(bobDataJson.data.length).toBe(0);

      const bobPollAliceRes = await app.request(`/api/credentials/${aliceCred.id}/poll`, {
        method: "POST",
        headers: { Cookie: bobCookie },
      });
      expect(bobPollAliceRes.status).toBe(404);
      const bobPollJson = (await bobPollAliceRes.json()) as { success: boolean; error?: string };
      expect(bobPollJson.success).toBe(false);
      expect(bobPollJson.error).toBe("Credential not found");
    } finally {
      rawDb.close();
      vault.close();
      try {
        rmSync(dbPath, { force: true });
        rmSync(`${dbPath}-wal`, { force: true });
        rmSync(`${dbPath}-shm`, { force: true });
      } catch {}
    }
  });
});

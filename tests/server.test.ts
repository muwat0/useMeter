import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer, computeAssetRevision } from "../src/server/app";
import type { FetchContext, ProviderAdapter } from "../src/core/providers/adapter";
import type { StoredCredential } from "../src/types";
describe("Server API Endpoints", () => {
  it("serves health, usage, credentials, and dashboard HTML", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    // 1. Health check
    const healthRes = await app.request("/health");
    expect(healthRes.status).toBe(200);
    const healthJson = (await healthRes.json()) as { status: string; integrity: boolean };
    expect(healthJson.status).toBe("ok");
    expect(healthJson.integrity).toBe(true);

    // Anonymous protected requests are rejected
    const anonAdd = await app.request("/api/credentials", { method: "POST" });
    expect(anonAdd.status).toBe(401);

    const anonRoot = await app.request("/");
    expect(anonRoot.status).toBe(302);

    // Register authenticated user
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "tester@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // 2. Add credential (authenticated)
    const addRes = await app.request("/api/credentials", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Test Key",
        credentialType: "api_key",
        secret: "sk-or-v1-super-secret-token",
      }),
    });
    expect(addRes.status).toBe(200);
    const addJson = (await addRes.json()) as { success: boolean; data: { id: string } };
    expect(addJson.success).toBe(true);
    expect(addJson.data.id).toBeDefined();

    // 3. List credentials (masked)
    const listRes = await app.request("/api/credentials", {
      headers: { Cookie: cookie },
    });
    expect(listRes.status).toBe(200);
    const listJson = (await listRes.json()) as { success: boolean; data: Array<{ maskedSecret: string }> };
    expect(listJson.data.length).toBe(1);
    expect(listJson.data[0]?.maskedSecret).toBe("sk-o...oken");

    // 4. Usage endpoint
    const usageRes = await app.request("/api/usage", {
      headers: { Cookie: cookie },
    });
    expect(usageRes.status).toBe(200);

    // 5. Dashboard HTML
    const htmlRes = await app.request("/", {
      headers: { Cookie: cookie },
    });
    expect(htmlRes.status).toBe(200);
    const html = await htmlRes.text();
    expect(html).toContain('id="app"');
    expect(html).toContain('/assets/app.js');
    expect(html).toContain('/assets/app.css');

    // 6. Poll all credentials for user
    const pollRes = await app.request("/api/poll", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(pollRes.status).toBe(200);

    // 7. Poll single credential
    const pollCredRes = await app.request(`/api/credentials/${addJson.data.id}/poll`, {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(pollCredRes.status).toBe(200);

    vault.close();
  });

  it("protects operational metrics and reports health, poller, and storage state to admins", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    const anonymous = await app.request("/api/admin/metrics");
    expect(anonymous.status).toBe(401);

    const adminRegister = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "metrics-admin@example.test", password: "Password12345678!" }),
    });
    expect(adminRegister.status).toBe(201);
    const adminCookie = adminRegister.headers.get("Set-Cookie")!.split(";")[0]!;

    const userRegister = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "metrics-user@example.test", password: "Password12345678!" }),
    });
    expect(userRegister.status).toBe(201);
    const userCookie = userRegister.headers.get("Set-Cookie")!.split(";")[0]!;
    const forbidden = await app.request("/api/admin/metrics", {
      headers: { Cookie: userCookie },
    });
    expect(forbidden.status).toBe(403);

    const response = await app.request("/api/admin/metrics", {
      headers: { Cookie: adminCookie },
    });
    expect(response.status).toBe(200);
    const metrics = await response.json() as {
      success: boolean;
      health: { integrity: boolean };
      poller: { running: boolean; lastSweepStatus: string; consecutiveSweepFailures: number };
      storage: {
        databaseSizeBytes: number;
        walSizeBytes: number;
        freePageCount: number;
        totalSnapshots: number;
        activeCredentials: number;
      };
      mailBridge: { configured: boolean; status: string };
      alertThresholds: {
        diskUsagePercent: number;
        consecutivePollerFailures: number;
        pollerMustBeRunning: boolean;
        databaseIntegrityRequired: boolean;
        mailBridgeReachabilityRequiredWhenConfigured: boolean;
      };
    };
    expect(metrics.success).toBe(true);
    expect(metrics.health.integrity).toBe(true);
    expect(metrics.poller.running).toBe(false);
    expect(metrics.poller.lastSweepStatus).toBe("never");
    expect(metrics.poller.consecutiveSweepFailures).toBe(0);
    expect(metrics.storage.databaseSizeBytes).toBeGreaterThanOrEqual(0);
    expect(metrics.storage.walSizeBytes).toBeGreaterThanOrEqual(0);
    expect(metrics.storage.freePageCount).toBeGreaterThanOrEqual(0);
    expect(metrics.storage.totalSnapshots).toBe(0);
    expect(metrics.storage.activeCredentials).toBe(0);
    expect(["disabled", "available", "unavailable"]).toContain(metrics.mailBridge.status);
    expect(metrics.alertThresholds.diskUsagePercent).toBe(90);
    expect(metrics.alertThresholds.consecutivePollerFailures).toBe(3);
    expect(metrics.alertThresholds.pollerMustBeRunning).toBe(true);
    expect(metrics.alertThresholds.databaseIntegrityRequired).toBe(true);
    expect(metrics.alertThresholds.mailBridgeReachabilityRequiredWhenConfigured).toBe(true);

    vault.close();
  });

  it("deletes an owner's credential and cascades usage history while rejecting other callers", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const app = createServer(vault, new PollerEngine(vault, registry, { minProviderIntervalMs: 0 }), registry);

    const register = async (email: string) => {
      const response = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: "Password12345678!" }),
      });
      expect(response.status).toBe(201);
      const body = await response.json() as { user: { id: string } };
      const setCookie = response.headers.get("Set-Cookie");
      expect(setCookie).toBeTruthy();
      return { userId: body.user.id, cookie: setCookie!.split(";")[0]! };
    };

    const owner = await register("credential-owner@example.test");
    const foreignUser = await register("credential-foreign@example.test");
    const credential = vault.saveCredential(owner.userId, {
      provider: "openrouter",
      accountLabel: "Owner test key",
      credentialType: "api_key",
      secret: "test-only-secret",
    });
    expect(vault.saveUsageSnapshot(owner.userId, {
      provider: "openrouter",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: Date.now(),
      limits: [],
    })).toBe(true);
    expect(vault.getSystemStatsAdmin(false).totalSnapshots).toBe(1);

    const anonymousDelete = await app.request(`/api/credentials/${credential.id}`, { method: "DELETE" });
    expect(anonymousDelete.status).toBe(401);

    const foreignDelete = await app.request(`/api/credentials/${credential.id}`, {
      method: "DELETE",
      headers: { Cookie: foreignUser.cookie },
    });
    expect(foreignDelete.status).toBe(404);
    expect(vault.getCredential(owner.userId, credential.id)).not.toBeNull();
    expect(vault.getSystemStatsAdmin(false).totalSnapshots).toBe(1);

    const ownerDelete = await app.request(`/api/credentials/${credential.id}`, {
      method: "DELETE",
      headers: { Cookie: owner.cookie },
    });
    expect(ownerDelete.status).toBe(200);
    const deleteResult = await ownerDelete.json() as { success: boolean };
    expect(deleteResult.success).toBe(true);
    expect(vault.getCredential(owner.userId, credential.id)).toBeNull();
    expect(vault.getSystemStatsAdmin(false).totalSnapshots).toBe(0);

    vault.close();
  });


  it("enforces security headers and rejects unverified cross-origin requests", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry(), { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, createDefaultRegistry());

    // Security headers on health
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
    expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(res.headers.get("Permissions-Policy")).toContain("camera=()");

    // CORS rejection of untrusted origin
    const corsRes = await app.request("/health", {
      headers: { Origin: "https://evil.com" },
    });
    expect(corsRes.headers.get("Access-Control-Allow-Origin")).toBeNull();

    vault.close();
  });

  it("handles rate limiting on authentication and polling endpoints", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry(), { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, createDefaultRegistry());

    // Register an admin user first
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // Exhaust auth login rate limit (limit is 5)
    for (let i = 0; i < 5; i++) {
      await app.request("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "admin@example.com", password: "WrongPassword123!" }),
      });
    }

    const blockedLogin = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Password12345678!" }),
    });
    expect(blockedLogin.status).toBe(429);
    expect(blockedLogin.headers.get("Retry-After")).toBeDefined();

    // Manual poll rate limit (limit is 1 per 30s)
    const poll1 = await app.request("/api/poll", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(poll1.status).toBe(200);

    const poll2 = await app.request("/api/poll", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(poll2.status).toBe(429);
    expect(poll2.headers.get("Retry-After")).toBeDefined();

    vault.close();
  });

  it("manages invitations via admin API and allows user onboarding when registration is disabled", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry(), { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, createDefaultRegistry());

    // 1. Create first user (admin)
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "owner@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const adminCookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // 2. Disable public registration
    vault.setRegistrationAllowed(false);
    expect(vault.isRegistrationAllowed()).toBe(false);

    // Public register should now be forbidden (403)
    const blockedReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "intruder@example.com", password: "Password12345678!" }),
    });
    expect(blockedReg.status).toBe(403);

    // 3. Admin creates invitation
    const createInvRes = await app.request("/api/admin/invitations", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: adminCookie,
      },
      body: JSON.stringify({ email: "invited@example.com" }),
    });
    expect(createInvRes.status).toBe(201);
    const createInvJson = (await createInvRes.json()) as { success: boolean; inviteUrl: string; token: string; invitation: { id: string } };
    expect(createInvJson.success).toBe(true);
    expect(createInvJson.inviteUrl).toContain("/invite/");
    expect(createInvJson.token).toBeDefined();

    // 4. Admin lists invitations (never leaks token/hash)
    const listInvRes = await app.request("/api/admin/invitations", {
      headers: { Cookie: adminCookie },
    });
    expect(listInvRes.status).toBe(200);
    const listInvJson = (await listInvRes.json()) as { success: boolean; data: Array<{ id: string; email: string; token?: string; tokenHash?: string }> };
    expect(listInvJson.data.length).toBe(1);
    expect(listInvJson.data[0]?.email).toBe("invited@example.com");
    expect(listInvJson.data[0]?.token).toBeUndefined();
    expect(listInvJson.data[0]?.tokenHash).toBeUndefined();

    // 5. Invited user visits invite page
    const invitePageRes = await app.request(`/invite/${createInvJson.token}`);
    expect(invitePageRes.status).toBe(200);
    const invitePageHtml = await invitePageRes.text();
    expect(invitePageHtml).toContain("Daveti Kabul Et");
    expect(invitePageHtml).toContain("Accept Invitation");

    // 6. Invited user accepts invitation with new password (works while registration is disabled!)
    const acceptRes = await app.request(`/api/invitations/${createInvJson.token}/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "NewUserPassword1234!" }),
    });
    expect(acceptRes.status).toBe(200);
    const acceptJson = (await acceptRes.json()) as { success: boolean; user: { id: string; email: string } };
    expect(acceptJson.success).toBe(true);
    expect(acceptJson.user.email).toBe("invited@example.com");
    const userCookie = acceptRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // 7. Verify newly onboarded user has role 'user' and can access protected usage
    const meRes = await app.request("/api/auth/me", {
      headers: { Cookie: userCookie },
    });
    expect(meRes.status).toBe(200);

    // 8. Replay of accepted invitation token must fail with generic 400
    const replayRes = await app.request(`/api/invitations/${createInvJson.token}/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "AnotherPassword123!" }),
    });
    expect(replayRes.status).toBe(400);

    // 9. Admin revokes another invitation
    const createInv2Res = await app.request("/api/admin/invitations", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: adminCookie,
      },
      body: JSON.stringify({ email: "revoked@example.com" }),
    });
    const createInv2Json = (await createInv2Res.json()) as { invitation: { id: string }; token: string };
    
    const revokeRes = await app.request(`/api/admin/invitations/${createInv2Json.invitation.id}`, {
      method: "DELETE",
      headers: { Cookie: adminCookie },
    });
    expect(revokeRes.status).toBe(200);

    // Accepting revoked invitation must fail with generic 400
    const acceptRevokedRes = await app.request(`/api/invitations/${createInv2Json.token}/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "SomeValidPassword123!" }),
    });
    expect(acceptRevokedRes.status).toBe(400);
    vault.close();
  });
});

describe("Server Asset Revision & Static Contract", () => {
  it("includes content digest in HTML asset URLs and serves immutable assets", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry(), { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, createDefaultRegistry());

    // Register user to access dashboard HTML
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "asset-test@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // 1. Dashboard HTML references content-addressed asset URLs
    const htmlRes = await app.request("/", {
      headers: { Cookie: cookie },
    });
    expect(htmlRes.status).toBe(200);
    expect(htmlRes.headers.get("Content-Security-Policy")).toContain("script-src 'self'");
    expect(htmlRes.headers.get("Content-Security-Policy")).toContain("style-src 'self' 'unsafe-inline'");

    const html = await htmlRes.text();

    // Must not use unversioned fixed URLs
    expect(html).not.toMatch(/<link\s+rel="stylesheet"\s+href="\/assets\/app\.css">/);
    expect(html).not.toMatch(/<script\s+type="module"\s+src="\/assets\/app\.js"><\/script>/);

    // Must match versioned URLs
    const cssMatch = html.match(/href="(\/assets\/app\.css\?v=([a-f0-9]+))"/);
    const jsMatch = html.match(/src="(\/assets\/app\.js\?v=([a-f0-9]+))"/);
    expect(cssMatch).not.toBeNull();
    expect(jsMatch).not.toBeNull();

    const cssUrl = cssMatch![1]!;
    const jsUrl = jsMatch![1]!;
    const cssRevision = cssMatch![2]!;
    const jsRevision = jsMatch![2]!;

    // Both assets share the bundle revision digest
    expect(cssRevision).toBe(jsRevision);

    // Compute expected digest from disk bytes
    const distDir = join(import.meta.dir, "../dist/client");
    if (existsSync(join(distDir, "app.js")) && existsSync(join(distDir, "app.css"))) {
      const expectedDigest = computeAssetRevision(distDir);
      expect(cssRevision).toBe(expectedDigest);

      // 2. GET referenced CSS asset
      const cssRes = await app.request(cssUrl);
      expect(cssRes.status).toBe(200);
      expect(cssRes.headers.get("Content-Type")).toBe("text/css");
      expect(cssRes.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
      const cssBytes = readFileSync(join(distDir, "app.css"));
      expect(cssRes.headers.get("Content-Length")).toBe(String(cssBytes.length));
      const cssBody = await cssRes.text();
      expect(cssBody).toBe(cssBytes.toString());

      // 3. HEAD referenced CSS asset
      const cssHead = await app.request(cssUrl, { method: "HEAD" });
      expect(cssHead.status).toBe(200);
      expect(cssHead.headers.get("Content-Type")).toBe("text/css");
      expect(cssHead.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
      expect(cssHead.headers.get("Content-Length")).toBe(String(cssBytes.length));
      const cssHeadBody = await cssHead.text();
      expect(cssHeadBody).toBe("");

      // 4. GET referenced JS asset
      const jsRes = await app.request(jsUrl);
      expect(jsRes.status).toBe(200);
      expect(jsRes.headers.get("Content-Type")).toBe("application/javascript");
      expect(jsRes.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
      const jsBytes = readFileSync(join(distDir, "app.js"));
      expect(jsRes.headers.get("Content-Length")).toBe(String(jsBytes.length));
      const jsBody = await jsRes.text();
      expect(jsBody).toBe(jsBytes.toString());

      // 5. HEAD referenced JS asset
      const jsHead = await app.request(jsUrl, { method: "HEAD" });
      expect(jsHead.status).toBe(200);
      expect(jsHead.headers.get("Content-Type")).toBe("application/javascript");
      expect(jsHead.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
      expect(jsHead.headers.get("Content-Length")).toBe(String(jsBytes.length));
      const jsHeadBody = await jsHead.text();
      expect(jsHeadBody).toBe("");
    }

    vault.close();
  });

  it("updates asset revision when Vite build rewrites asset content", async () => {
    const tempDist = mkdtempSync(join(tmpdir(), "usemeter-test-dist-"));
    try {
      // 1. Initial build output
      writeFileSync(join(tempDist, "app.js"), "console.log('build-v1');");
      writeFileSync(join(tempDist, "app.css"), "body { color: blue; }");

      const vault1 = new StorageVault(":memory:");
      const poller1 = new PollerEngine(vault1, createDefaultRegistry(), { minProviderIntervalMs: 0 });
      const app1 = createServer(vault1, poller1, createDefaultRegistry(), undefined, { distDir: tempDist });

      const reg1 = await app1.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "build1@example.com", password: "Password12345678!" }),
      });
      const cookie1 = reg1.headers.get("Set-Cookie")!.split(";")[0]!;

      const html1Res = await app1.request("/", { headers: { Cookie: cookie1 } });
      const html1 = await html1Res.text();
      const match1 = html1.match(/src="\/assets\/app\.js\?v=([a-f0-9]+)"/);
      expect(match1).not.toBeNull();
      const revision1 = match1![1]!;

      // 2. Vite rebuild rewrites app.js
      writeFileSync(join(tempDist, "app.js"), "console.log('build-v2-new-ui');");

      const vault2 = new StorageVault(":memory:");
      const poller2 = new PollerEngine(vault2, createDefaultRegistry(), { minProviderIntervalMs: 0 });
      const app2 = createServer(vault2, poller2, createDefaultRegistry(), undefined, { distDir: tempDist });

      const reg2 = await app2.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "build2@example.com", password: "Password12345678!" }),
      });
      const cookie2 = reg2.headers.get("Set-Cookie")!.split(";")[0]!;

      const html2Res = await app2.request("/", { headers: { Cookie: cookie2 } });
      const html2 = await html2Res.text();
      const match2 = html2.match(/src="\/assets\/app\.js\?v=([a-f0-9]+)"/);
      expect(match2).not.toBeNull();
      const revision2 = match2![1]!;

      // Fresh deployment HTML must reference new URL whenever bundle bytes change
      expect(revision2).not.toBe(revision1);

      // New asset URL serves updated content with immutable cache headers
      const newJsRes = await app2.request(`/assets/app.js?v=${revision2}`);
      expect(newJsRes.status).toBe(200);
      expect(newJsRes.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
      expect(await newJsRes.text()).toBe("console.log('build-v2-new-ui');");

      vault1.close();
      vault2.close();
    } finally {
      rmSync(tempDist, { recursive: true, force: true });
    }
  });

  it("handles missing dist gracefully as 404 without crashing and blocks path traversal", async () => {
    const nonexistentDist = join(tmpdir(), "usemeter-nonexistent-dist-" + Date.now());
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry(), { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, createDefaultRegistry(), undefined, { distDir: nonexistentDist });

    const reg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "nodist@example.com", password: "Password12345678!" }),
    });
    const cookie = reg.headers.get("Set-Cookie")!.split(";")[0]!;

    // Dashboard renders safely without crashing
    const htmlRes = await app.request("/", { headers: { Cookie: cookie } });
    expect(htmlRes.status).toBe(200);
    const html = await htmlRes.text();
    expect(html).toContain('id="app"');

    // Missing assets return existing 404 rather than 500 crash
    const jsRes = await app.request("/assets/app.js");
    expect(jsRes.status).toBe(404);

    const cssRes = await app.request("/assets/app.css");
    expect(cssRes.status).toBe(404);

    const jsHeadRes = await app.request("/assets/app.js", { method: "HEAD" });
    expect(jsHeadRes.status).toBe(404);

    // Traversal attempts blocked with 403
    const traversalRes = await app.request("/assets/..%2fpackage.json");
    expect(traversalRes.status).toBe(403);

    vault.close();
  });
});

describe("Manual Credential Route Safe Validation & Isolation", () => {
  it("rejects invalid new manual credential, saving nothing to vault and recording zero snapshots", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "invalid-manual@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = (await regRes.json() as { user: { id: string } }).user;

    // Submit an invalid manual credential: Kimi Code rejects api_key credentialType
    const addRes = await app.request("/api/credentials", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({
        provider: "kimi-code",
        accountLabel: "Invalid Key",
        credentialType: "api_key",
        secret: "sk-invalid-test-key",
      }),
    });
    expect(addRes.status).toBe(400);
    const addJson = await addRes.json() as { success: boolean; error: string };
    expect(addJson.success).toBe(false);
    expect(addJson.error).toContain("OAuth");

    // CRITICAL: Absolutely nothing saved to database
    expect(vault.listCredentials(user.id)).toHaveLength(0);
    expect(vault.getSystemStatsAdmin(false).totalSnapshots).toBe(0);

    vault.close();
  });

  it("preserves existing credential, secret, accent, and snapshots when repeat manual credential POST fails validation", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();

    const mockAdapter: ProviderAdapter = {
      id: "manual-mock",
      supports: (p: string) => p.toLowerCase() === "manual-mock",
      fetchUsage: async (cred: StoredCredential) => {
        if (cred.secret === "bad-secret") {
          throw new Error("Provider rejected bad secret");
        }
        return {
          provider: "manual-mock",
          credentialId: cred.id,
          accountLabel: cred.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          source: "live",
        };
      },
    };
    registry.register(mockAdapter);

    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "repeat-manual@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = (await regRes.json() as { user: { id: string } }).user;

    // 1. Initial valid credential
    const initRes = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "manual-mock",
        accountLabel: "Production Key",
        credentialType: "api_key",
        secret: "good-initial-secret",
        accent: "emerald",
        metadata: { refreshToken: "old-refresh", accountId: "old-account", email: "old@example.com" },
      }),
    });
    expect(initRes.status).toBe(200);
    const initJson = await initRes.json() as { success: boolean; data: { id: string } };
    const credentialId = initJson.data.id;

    // Add an extra historical snapshot
    vault.saveUsageSnapshot(user.id, {
      provider: "manual-mock",
      credentialId,
      accountLabel: "Production Key",
      fetchedAt: Date.now() - 5000,
      limits: [],
      health: "healthy",
      source: "live",
    });
    const baselineSnapshots = vault.getSnapshotHistory(user.id, "manual-mock", 24);
    expect(baselineSnapshots.length).toBeGreaterThanOrEqual(2);

    // 2. Repeat manual POST with SAME accountLabel but invalid secret
    const repeatRes = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "manual-mock",
        accountLabel: "Production Key",
        credentialType: "api_key",
        secret: "bad-secret",
        accent: "violet",
      }),
    });
    expect(repeatRes.status).toBe(400);
    const repeatJson = await repeatRes.json() as { success: boolean; error: string };
    expect(repeatJson.success).toBe(false);
    expect(repeatJson.error).toBe("Provider rejected bad secret");

    // 3. CRITICAL: Existing credential, secret, accent, and snapshots MUST be preserved (NOT deleted by upsert-then-delete cascade)
    expect(vault.listCredentials(user.id, "manual-mock")).toHaveLength(1);
    const credAfterFailure = vault.getCredential(user.id, credentialId);
    expect(credAfterFailure).not.toBeNull();
    expect(credAfterFailure?.secret).toBe("good-initial-secret");
    expect(credAfterFailure?.accent).toBe("emerald");
    expect(credAfterFailure?.metadata).toMatchObject({
      refreshToken: "old-refresh",
      accountId: "old-account",
      email: "old@example.com",
    });
    expect(vault.getSnapshotHistory(user.id, "manual-mock", 24)).toHaveLength(baselineSnapshots.length);

    vault.close();
  });

  it("protects anonymous callers, ignores spoofed ownerId, and isolates credentials between tenants", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    // Anonymous rejected
    const anonRes = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Anon Key",
        credentialType: "api_key",
        secret: "sk-or-v1-anon-secret-token",
      }),
    });
    expect(anonRes.status).toBe(401);

    // Tenant 1 registers
    const reg1 = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "tenant1@example.com", password: "Password12345678!" }),
    });
    const cookie1 = reg1.headers.get("Set-Cookie")!.split(";")[0]!;
    const user1 = (await reg1.json() as { user: { id: string } }).user;

    // Tenant 2 registers
    const reg2 = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "tenant2@example.com", password: "Password12345678!" }),
    });
    const cookie2 = reg2.headers.get("Set-Cookie")!.split(";")[0]!;
    const user2 = (await reg2.json() as { user: { id: string } }).user;

    // Tenant 1 adds credential attempting to spoof ownerId to user2.id
    const add1 = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie1 },
      body: JSON.stringify({
        ownerId: user2.id, // spoof attempt
        provider: "openrouter",
        accountLabel: "Shared Key Label",
        credentialType: "api_key",
        secret: "sk-or-v1-tenant1-secret",
      }),
    });
    expect(add1.status).toBe(200);
    const cred1 = (await add1.json() as { data: { id: string } }).data;

    // Spoofed ownerId ignored: credential belongs strictly to user1
    expect(vault.getCredential(user1.id, cred1.id)).not.toBeNull();
    expect(vault.getCredential(user2.id, cred1.id)).toBeNull();
    expect(vault.listCredentials(user2.id)).toHaveLength(0);

    // Tenant 2 adds credential with the same account label
    const add2 = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie2 },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Shared Key Label",
        credentialType: "api_key",
        secret: "sk-or-v1-tenant2-secret",
      }),
    });
    expect(add2.status).toBe(200);
    const cred2 = (await add2.json() as { data: { id: string } }).data;

    expect(cred1.id).not.toBe(cred2.id);
    expect(vault.listCredentials(user1.id)).toHaveLength(1);
    expect(vault.listCredentials(user2.id)).toHaveLength(1);

    vault.close();
  });

  it("preserves submitted manual accountLabel and existing credential identity when provider adapter proposes a new label during validation (Cursor/Devin-like behavior)", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();

    let fetchCalls = 0;
    let pollMetadata: Record<string, unknown> | undefined;
    const mockAdapter: ProviderAdapter = {
      id: "cursor-like",
      supports: (p: string) => p.toLowerCase() === "cursor-like",
      fetchUsage: async (cred: StoredCredential, ctx?: FetchContext) => {
        fetchCalls += 1;
        if (cred.secret === "key-reauth-updated") {
          pollMetadata = cred.metadata;
          if (cred.metadata?.["accountId"] === "old-account") {
            ctx?.onTokenRefresh?.("old-account-refreshed-access", {
              refreshToken: "old-refresh",
              accountId: "old-account",
            });
          }
        }
        // Provider adapter proposes a discovered email onTokenRefresh
        ctx?.onTokenRefresh?.(cred.secret, { tokenType: "bearer" }, "discovered-user@example.com");
        return {
          provider: "cursor-like",
          credentialId: cred.id,
          accountLabel: cred.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          source: "live",
        };
      },
    };
    registry.register(mockAdapter);

    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "cursor-user@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = (await regRes.json() as { user: { id: string } }).user;

    // 1. Initial manual credential with user-supplied account label "Personal Dev"
    const initRes = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "cursor-like",
        accountLabel: "Personal Dev",
        credentialType: "api_key",
        secret: "key-initial",
        accent: "emerald",
        metadata: { refreshToken: "old-refresh", accountId: "old-account", email: "old@example.com" },
      }),
    });
    expect(initRes.status).toBe(200);
    const initJson = await initRes.json() as { success: boolean; data: { id: string; accountLabel: string; accent: string } };
    const credentialId = initJson.data.id;
    expect(initJson.data.accountLabel).toBe("Personal Dev");
    expect(initJson.data.accent).toBe("emerald");

    // Verify stored credential in vault
    const initialCred = vault.getCredential(user.id, credentialId);
    expect(initialCred).not.toBeNull();
    expect(initialCred?.accountLabel).toBe("Personal Dev");
    expect(initialCred?.accent).toBe("emerald");
    expect(vault.listCredentials(user.id, "cursor-like")).toHaveLength(1);

    const baselineSnapshots = vault.getSnapshotHistory(user.id, "cursor-like", 24);
    expect(baselineSnapshots).toHaveLength(1);
    expect(baselineSnapshots[0]?.accountLabel).toBe("Personal Dev");

    // 2. Repeat manual reauth under the SAME user-supplied label "Personal Dev",
    // with new secret, omitting accent. Adapter will again suggest "discovered-user@example.com".
    const repeatRes = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "cursor-like",
        accountLabel: "Personal Dev",
        credentialType: "api_key",
        secret: "key-reauth-updated",
      }),
    });
    expect(repeatRes.status).toBe(200);
    const repeatJson = await repeatRes.json() as { success: boolean; data: { id: string; accountLabel: string; accent: string } };

    // CRITICAL: ID and accountLabel are preserved! No duplicate credential created with the discovered email!
    expect(repeatJson.data.id).toBe(credentialId);
    expect(repeatJson.data.accountLabel).toBe("Personal Dev");
    expect(repeatJson.data.accent).toBe("emerald");

    const credentialsAfter = vault.listCredentials(user.id, "cursor-like");
    expect(credentialsAfter).toHaveLength(1);
    expect(credentialsAfter[0]?.id).toBe(credentialId);
    expect(credentialsAfter[0]?.accountLabel).toBe("Personal Dev");
    expect(credentialsAfter[0]?.secret).toBe("key-reauth-updated");
    expect(credentialsAfter[0]?.metadata).toMatchObject({ tokenType: "bearer" });
    expect(credentialsAfter[0]?.metadata?.["refreshToken"]).toBeUndefined();
    expect(credentialsAfter[0]?.metadata?.["accountId"]).toBeUndefined();
    expect(credentialsAfter[0]?.metadata?.["email"]).toBeUndefined();

    const pollReport = await poller.pollCredential(user.id, credentialId);
    expect(pollReport).not.toBeNull();
    expect(pollReport?.stale).toBe(false);
    expect(pollReport?.error).toBeUndefined();
    expect(pollMetadata).toMatchObject({ tokenType: "bearer" });
    expect(pollMetadata?.["accountId"]).toBeUndefined();
    expect(vault.getCredential(user.id, credentialId)).toMatchObject({
      secret: "key-reauth-updated",
      metadata: { tokenType: "bearer" },
    });

    // Snapshots appended to the same credential history
    const snapshotsAfter = vault.getSnapshotHistory(user.id, "cursor-like", 24);
    expect(snapshotsAfter).toHaveLength(3);
    expect(credentialsAfter[0]?.accent).toBe("emerald");

    expect(snapshotsAfter.every(snapshot => snapshot.credentialId === credentialId)).toBe(true);

    vault.close();
  });

  it("retains existing credential identity without collision when repeating an existing generic label alongside another credential", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();

    const mockAdapter: ProviderAdapter = {
      id: "devin-like",
      supports: (p: string) => p.toLowerCase() === "devin-like",
      fetchUsage: async (cred: StoredCredential, ctx?: FetchContext) => {
        // Proposes another label that might conflict
        ctx?.onTokenRefresh?.(cred.secret, { session: "active" }, "Work Devin");
        return {
          provider: "devin-like",
          credentialId: cred.id,
          accountLabel: cred.accountLabel,
          fetchedAt: Date.now(),
          limits: [],
          health: "healthy",
          source: "live",
        };
      },
    };
    registry.register(mockAdapter);

    const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
    const app = createServer(vault, poller, registry);

    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "devin-multi@example.com", password: "Password12345678!" }),
    });
    expect(regRes.status).toBe(201);
    const cookie = regRes.headers.get("Set-Cookie")!.split(";")[0]!;
    const user = (await regRes.json() as { user: { id: string } }).user;

    // Credential 1: generic label "Devin"
    const cred1Res = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "devin-like",
        accountLabel: "Devin",
        credentialType: "api_key",
        secret: "devin-key-1",
        accent: "cyan",
      }),
    });
    expect(cred1Res.status).toBe(200);
    const cred1Id = (await cred1Res.json() as { data: { id: string } }).data.id;

    // Credential 2: label "Work Devin"
    const cred2Res = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "devin-like",
        accountLabel: "Work Devin",
        credentialType: "api_key",
        secret: "devin-key-2",
        accent: "violet",
      }),
    });
    expect(cred2Res.status).toBe(200);
    const cred2Id = (await cred2Res.json() as { data: { id: string } }).data.id;

    expect(vault.listCredentials(user.id, "devin-like")).toHaveLength(2);

    // Now re-authorize generic "Devin", while adapter suggests "Work Devin" (which would collide with Credential 2!)
    const reauth1Res = await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        provider: "devin-like",
        accountLabel: "Devin",
        credentialType: "api_key",
        secret: "devin-key-1-refreshed",
      }),
    });
    expect(reauth1Res.status).toBe(200);
    const reauth1Data = (await reauth1Res.json() as { data: { id: string; accountLabel: string; accent: string } }).data;

    // Must retain cred1Id, not collide with Work Devin, not duplicate
    expect(reauth1Data.id).toBe(cred1Id);
    expect(reauth1Data.accountLabel).toBe("Devin");
    expect(reauth1Data.accent).toBe("cyan");

    const allCreds = vault.listCredentials(user.id, "devin-like");
    expect(allCreds).toHaveLength(2);
    const c1 = allCreds.find(c => c.id === cred1Id);
    const c2 = allCreds.find(c => c.id === cred2Id);
    expect(c1?.accountLabel).toBe("Devin");
    expect(c1?.secret).toBe("devin-key-1-refreshed");
    expect(c1?.accent).toBe("cyan");
    expect(c2?.accountLabel).toBe("Work Devin");
    expect(c2?.secret).toBe("devin-key-2");

    vault.close();
  });
});

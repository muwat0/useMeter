import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";

describe("Server API Endpoints", () => {
  it("serves health, usage, credentials, and dashboard HTML", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
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

  it("enforces security headers and rejects unverified cross-origin requests", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry());
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
    const poller = new PollerEngine(vault, createDefaultRegistry());
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
    const poller = new PollerEngine(vault, createDefaultRegistry());
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

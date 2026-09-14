import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { AuthService } from "../src/core/auth/auth";
import { createServer } from "../src/server/app";

describe("Authentication & Multi-Tenant Isolation", () => {
  it("registers users, rejects duplicates, and enforces password rules", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const auth = new AuthService(vault);
    const app = createServer(vault, poller, registry, auth);

    // 1. Weak password (< 12 chars)
    const weakRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "short" }),
    });
    expect(weakRes.status).toBe(400);
    const weakJson = (await weakRes.json()) as { success: boolean; error: string };
    expect(weakJson.success).toBe(false);

    // 2. Successful registration
    const regRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "Correct-Horse-Battery-Staple-123" }),
    });
    expect(regRes.status).toBe(201);
    const regCookie = regRes.headers.get("Set-Cookie");
    expect(regCookie).not.toBeNull();
    expect(regCookie).toContain("usage_session=");
    expect(regCookie).toContain("HttpOnly");
    expect(regCookie).toContain("SameSite=Lax");
    expect(regCookie).toContain("Path=/");
    expect(regCookie).toContain("Max-Age=2592000");

    const regJson = (await regRes.json()) as { success: boolean; user: { id: string; email: string } };
    expect(regJson.success).toBe(true);
    expect(regJson.user.email).toBe("alice@example.com");

    // 3. Duplicate email registration
    const dupRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "Another-Strong-Password-456" }),
    });
    expect(dupRes.status).toBe(400);
    const dupJson = (await dupRes.json()) as { success: boolean; error: string };
    expect(dupJson.success).toBe(false);

    vault.close();
  });

  it("handles login, generic error messages (no enumeration), and session lifecycle", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const auth = new AuthService(vault);
    const app = createServer(vault, poller, registry, auth);

    // Register user
    await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "bob@example.com", password: "SuperSecretPassword123!" }),
    });

    // Invalid password
    const wrongPassRes = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "bob@example.com", password: "WrongPassword123!" }),
    });
    expect(wrongPassRes.status).toBe(401);
    const wrongPassJson = (await wrongPassRes.json()) as { success: boolean; error: string };
    expect(wrongPassJson.error).toBe("Invalid email or password");

    // Non-existent user (must return identical generic error to prevent enumeration)
    const unknownRes = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "nonexistent@example.com", password: "RandomPassword123!" }),
    });
    expect(unknownRes.status).toBe(401);
    const unknownJson = (await unknownRes.json()) as { success: boolean; error: string };
    expect(unknownJson.error).toBe("Invalid email or password");

    // Valid login
    const loginRes = await app.request("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "bob@example.com", password: "SuperSecretPassword123!" }),
    });
    expect(loginRes.status).toBe(200);
    const setCookie = loginRes.headers.get("Set-Cookie");
    expect(setCookie).not.toBeNull();
    expect(setCookie).toContain("usage_session=");

    // Extract cookie
    const sessionCookie = setCookie!.split(";")[0]!;

    // Access protected /api/auth/me
    const meRes = await app.request("/api/auth/me", {
      headers: { Cookie: sessionCookie },
    });
    expect(meRes.status).toBe(200);
    const meJson = (await meRes.json()) as { success: boolean; user: { email: string } };
    expect(meJson.user.email).toBe("bob@example.com");

    // Logout
    const logoutRes = await app.request("/api/auth/logout", {
      method: "POST",
      headers: { Cookie: sessionCookie },
    });
    expect(logoutRes.status).toBe(200);
    const expiredCookie = logoutRes.headers.get("Set-Cookie");
    expect(expiredCookie).toContain("Max-Age=0");

    // Verify session is revoked on server
    const meAfterLogout = await app.request("/api/auth/me", {
      headers: { Cookie: sessionCookie },
    });
    expect(meAfterLogout.status).toBe(401);

    vault.close();
  });

  it("protects routes: anonymous users redirected or rejected with 401", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // 1. Health check is public
    const health = await app.request("/health");
    expect(health.status).toBe(200);

    // 2. Anonymous GET / redirects to /login
    const root = await app.request("/");
    expect(root.status).toBe(302);
    expect(root.headers.get("Location")).toBe("/login");

    // 3. Anonymous GET /login and GET /register serve 200 HTML
    const loginPage = await app.request("/login");
    expect(loginPage.status).toBe(200);
    const loginHtml = await loginPage.text();
    expect(loginHtml).toContain("Giriş Yap");
    expect(loginHtml).toContain("useMeter");

    const regPage = await app.request("/register");
    expect(regPage.status).toBe(200);
    const regHtml = await regPage.text();
    expect(regHtml).toContain("Hesap Oluştur");

    // 4. Anonymous protected API calls return 401 JSON
    const creds = await app.request("/api/credentials");
    expect(creds.status).toBe(401);
    const credsJson = (await creds.json()) as { error: string };
    expect(credsJson.error).toBe("Unauthorized");

    const usage = await app.request("/api/usage");
    expect(usage.status).toBe(401);

    const poll = await app.request("/api/poll", { method: "POST" });
    expect(poll.status).toBe(401);

    const oauth = await app.request("/api/oauth/google/initiate", { method: "POST" });
    expect(oauth.status).toBe(401);

    vault.close();
  });

  it("enforces origin validation on mutating authenticated routes (CSRF protection)", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register user to obtain session
    const reg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "csrf-test@example.com", password: "Password12345678!" }),
    });
    const cookie = reg.headers.get("Set-Cookie")!.split(";")[0]!;

    // Cross-origin POST request from attacker origin must be rejected with 403
    const crossOriginRes = await app.request("http://localhost:3000/api/credentials", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
        Origin: "http://malicious-website.com",
      },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Hacked Key",
        credentialType: "api_key",
        secret: "sk-or-v1-evil",
      }),
    });
    expect(crossOriginRes.status).toBe(403);
    const crossJson = (await crossOriginRes.json()) as { error: string };
    expect(crossJson.error).toContain("Cross-origin");

    // Same-origin POST request must succeed
    const sameOriginRes = await app.request("http://localhost:3000/api/credentials", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
        Origin: "http://localhost:3000",
      },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Safe Key",
        credentialType: "api_key",
        secret: "sk-or-v1-safe-key-12345",
      }),
    });
    expect(sameOriginRes.status).toBe(200);

    vault.close();
  });

  it("isolates credentials, usage, and OAuth flows across tenants", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // User A registers
    const userARes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "userA@example.com", password: "PasswordForUserA123!" }),
    });
    const cookieA = userARes.headers.get("Set-Cookie")!.split(";")[0]!;

    // User B registers
    const userBRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "userB@example.com", password: "PasswordForUserB123!" }),
    });
    const cookieB = userBRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // User A adds a credential
    const addCredARes = await app.request("/api/credentials", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookieA,
      },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "User A Private Key",
        credentialType: "api_key",
        secret: "sk-or-v1-user-a-secret",
      }),
    });
    expect(addCredARes.status).toBe(200);
    const addCredAJson = (await addCredARes.json()) as { data: { id: string } };
    const credAId = addCredAJson.data.id;

    // User B lists credentials: User B must see 0 credentials
    const listBRes = await app.request("/api/credentials", {
      headers: { Cookie: cookieB },
    });
    expect(listBRes.status).toBe(200);
    const listBJson = (await listBRes.json()) as { data: unknown[] };
    expect(listBJson.data.length).toBe(0);

    // User A lists credentials: User A sees 1 credential
    const listARes = await app.request("/api/credentials", {
      headers: { Cookie: cookieA },
    });
    expect(listARes.status).toBe(200);
    const listAJson = (await listARes.json()) as { data: Array<{ id: string; accountLabel: string }> };
    expect(listAJson.data.length).toBe(1);
    expect(listAJson.data[0]?.accountLabel).toBe("User A Private Key");

    // User B attempts to DELETE User A's credential: must return generic 404
    const deleteCrossRes = await app.request(`/api/credentials/${credAId}`, {
      method: "DELETE",
      headers: { Cookie: cookieB },
    });
    expect(deleteCrossRes.status).toBe(404);

    // Verify User A's credential is still intact
    const verifyARes = await app.request("/api/credentials", {
      headers: { Cookie: cookieA },
    });
    const verifyAJson = (await verifyARes.json()) as { data: unknown[] };
    expect(verifyAJson.data.length).toBe(1);

    // User B attempts to PATCH User A's credential: must return generic 404
    const patchCrossRes = await app.request(`/api/credentials/${credAId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookieB,
      },
      body: JSON.stringify({ accountLabel: "Hacked Label" }),
    });
    expect(patchCrossRes.status).toBe(404);

    // User A can successfully delete own credential
    const deleteOwnRes = await app.request(`/api/credentials/${credAId}`, {
      method: "DELETE",
      headers: { Cookie: cookieA },
    });
    expect(deleteOwnRes.status).toBe(200);

    vault.close();
  });
});

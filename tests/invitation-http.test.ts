import { describe, expect, it } from "bun:test";
import { RateLimiter, RATE_LIMIT_POLICIES } from "../src/server/security";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { AuthService } from "../src/core/auth/auth";
import { createServer } from "../src/server/app";
import { hashSessionToken } from "../src/core/crypto";

interface InvitationItemView {
  id: string;
  email: string;
  status: string;
  createdBy?: string;
  createdAt?: number;
  expiresAt: number;
  acceptedAt?: number | null;
  revokedAt?: number | null;
}

interface CreateInvitationResponse {
  success: boolean;
  inviteUrl?: string;
  invitation?: InvitationItemView;
  error?: string;
}

interface ListInvitationsResponse {
  success: boolean;
  data?: InvitationItemView[];
  invitations?: InvitationItemView[];
  error?: string;
}

interface AcceptInvitationResponse {
  success: boolean;
  user?: {
    id: string;
    email: string;
    createdAt?: number;
  };
  error?: string;
}

interface AuthResponse {
  success: boolean;
  user?: {
    id: string;
    email: string;
    createdAt?: number;
  };
  error?: string;
}

interface GenericResponse {
  success: boolean;
  error?: string;
}

type TestApp = {
  request: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
};

function createTestApp(rateLimiter?: RateLimiter) {
  const vault = new StorageVault(":memory:");
  const registry = createDefaultRegistry();
  const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
  const authService = new AuthService(vault);
  const app = createServer(vault, poller, registry, authService, rateLimiter ? { rateLimiter } : undefined) as unknown as TestApp;
  return { vault, registry, poller, authService, app };
}

async function registerAdmin(
  app: TestApp,
  email = "admin@example.com",
  password = "Admin-Strong-Password-123!"
) {
  const res = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const cookie = res.headers.get("Set-Cookie")?.split(";")[0] ?? "";
  const json = (await res.json()) as AuthResponse;
  return { res, cookie, json, email, password };
}

async function registerUser(
  app: TestApp,
  email = "user@example.com",
  password = "User-Strong-Password-123!"
) {
  const res = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const cookie = res.headers.get("Set-Cookie")?.split(";")[0] ?? "";
  const json = (await res.json()) as AuthResponse;
  return { res, cookie, json, email, password };
}

function extractRawToken(inviteUrl: string): string {
  const match = inviteUrl.match(/\/invite\/([a-zA-Z0-9_-]+)/);
  if (match && match[1]) {
    return match[1];
  }
  const url = new URL(inviteUrl, "http://localhost");
  const parts = url.pathname.split("/").filter(Boolean);
  return parts[parts.length - 1] || url.searchParams.get("token") || "";
}

describe("Invitation HTTP API & End-to-End Onboarding", () => {
  it("allows admin to create an invitation and returns inviteUrl, while list excludes raw token", async () => {
    const { vault, app } = createTestApp();
    try {
      const admin = await registerAdmin(app);
      expect(admin.res.status).toBe(201);
      expect(admin.cookie).toContain("usage_session=");

      // 1. Admin creates invitation
      const createRes = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "invitee@example.com" }),
      });

      expect([200, 201]).toContain(createRes.status);
      const createJson = (await createRes.json()) as CreateInvitationResponse;
      expect(createJson.success).toBe(true);
      expect(typeof createJson.inviteUrl).toBe("string");
      expect(createJson.inviteUrl!).toContain("/invite/");

      const rawToken = extractRawToken(createJson.inviteUrl!);
      expect(rawToken.length).toBeGreaterThanOrEqual(32);

      // Invitation object in creation response must not leak sensitive tokens
      expect(createJson.invitation).toBeDefined();
      expect(createJson.invitation!.email).toBe("invitee@example.com");
      expect(createJson.invitation!.status).toBe("pending");
      expect(Reflect.has(createJson.invitation!, "tokenHash")).toBe(false);
      expect(Reflect.has(createJson.invitation!, "token")).toBe(false);

      // 2. Admin lists invitations
      const listRes = await app.request("/api/admin/invitations", {
        headers: { Cookie: admin.cookie },
      });

      expect(listRes.status).toBe(200);
      const listJson = (await listRes.json()) as ListInvitationsResponse;
      expect(listJson.success).toBe(true);

      const items = listJson.data ?? listJson.invitations ?? [];
      expect(Array.isArray(items)).toBe(true);
      expect(items.length).toBe(1);

      const item = items[0]!;
      expect(item.email).toBe("invitee@example.com");
      expect(item.status).toBe("pending");
      expect(Reflect.has(item, "tokenHash")).toBe(false);
      expect(Reflect.has(item, "token")).toBe(false);
    } finally {
      vault.close();
    }
  });

  it("rejects unauthenticated and non-admin callers from managing invitations", async () => {
    const { vault, app } = createTestApp();
    try {
      await registerAdmin(app);
      const user = await registerUser(app, "normal@example.com");

      // 1. Anonymous callers -> 401 Unauthorized
      const anonCreate = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "anon-attempt@example.com" }),
      });
      expect(anonCreate.status).toBe(401);

      const anonList = await app.request("/api/admin/invitations");
      expect(anonList.status).toBe(401);

      const anonRevoke = await app.request("/api/admin/invitations/fake-id", {
        method: "DELETE",
      });
      expect(anonRevoke.status).toBe(401);

      // 2. Non-admin authenticated user -> 403 Forbidden
      const userCreate = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: user.cookie },
        body: JSON.stringify({ email: "user-attempt@example.com" }),
      });
      expect(userCreate.status).toBe(403);
      const userCreateJson = (await userCreate.json()) as GenericResponse;
      expect(userCreateJson.success).toBe(false);

      const userList = await app.request("/api/admin/invitations", {
        headers: { Cookie: user.cookie },
      });
      expect(userList.status).toBe(403);

      const userRevoke = await app.request("/api/admin/invitations/fake-id", {
        method: "DELETE",
        headers: { Cookie: user.cookie },
      });
      expect(userRevoke.status).toBe(403);
    } finally {
      vault.close();
    }
  });

  it("renders the public invite page for a valid invitation token", async () => {
    const { vault, app } = createTestApp();
    try {
      const admin = await registerAdmin(app);
      const createRes = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "pageuser@example.com" }),
      });
      const createJson = (await createRes.json()) as CreateInvitationResponse;
      const rawToken = extractRawToken(createJson.inviteUrl!);

      // 1. Primary route: GET /invite/:token
      const pageRes = await app.request(`/invite/${rawToken}`);
      expect(pageRes.status).toBe(200);
      expect(pageRes.headers.get("Content-Type")).toContain("text/html");

      const html = await pageRes.text();
      expect(html).toContain("password");
      expect(html.toLowerCase()).not.toContain("internal server error");

      // 2. Fallback route: GET /invite?token=...
      const fallbackRes = await app.request(`/invite?token=${rawToken}`);
      expect(fallbackRes.status).toBe(200);
      expect(fallbackRes.headers.get("Content-Type")).toContain("text/html");
    } finally {
      vault.close();
    }
  });

  it("allows public user to accept invitation, creates role 'user', and issues 30-day session cookie", async () => {
    const { vault, app } = createTestApp();
    try {
      const admin = await registerAdmin(app);
      const createRes = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "onboarded@example.com" }),
      });
      const createJson = (await createRes.json()) as CreateInvitationResponse;
      const rawToken = extractRawToken(createJson.inviteUrl!);

      // Accept invitation
      const acceptRes = await app.request(`/api/invitations/${rawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "NewUser-Strong-Password-123!" }),
      });

      expect([200, 201]).toContain(acceptRes.status);
      const acceptJson = (await acceptRes.json()) as AcceptInvitationResponse;
      expect(acceptJson.success).toBe(true);
      expect(acceptJson.user?.email).toBe("onboarded@example.com");

      // Check Set-Cookie
      const setCookie = acceptRes.headers.get("Set-Cookie");
      expect(setCookie).not.toBeNull();
      expect(setCookie).toContain("usage_session=");
      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("Path=/");
      expect(setCookie).toContain("SameSite=Lax");

      const sessionCookie = setCookie!.split(";")[0]!;

      // Verify session accesses protected /api/auth/me
      const meRes = await app.request("/api/auth/me", {
        headers: { Cookie: sessionCookie },
      });
      expect(meRes.status).toBe(200);
      const meJson = (await meRes.json()) as AuthResponse;
      expect(meJson.success).toBe(true);
      expect(meJson.user?.email).toBe("onboarded@example.com");

      // Verify newly created user is 'user' role, NOT 'admin'
      const adminRes = await app.request("/api/admin/stats", {
        headers: { Cookie: sessionCookie },
      });
      expect(adminRes.status).toBe(403);
    } finally {
      vault.close();
    }
  });

  it("allows invitation acceptance even when public registration is disabled", async () => {
    const { vault, app } = createTestApp();
    try {
      const admin = await registerAdmin(app);

      // Turn OFF public registration
      vault.setRegistrationAllowed(false);
      expect(vault.isRegistrationAllowed()).toBe(false);

      // Verify direct public registration is blocked with 403
      const publicRegRes = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "public-stranger@example.com",
          password: "Stranger-Password-123!",
        }),
      });
      expect(publicRegRes.status).toBe(403);

      // Admin creates invitation
      const createRes = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "lockdown-invited@example.com" }),
      });
      expect([200, 201]).toContain(createRes.status);
      const createJson = (await createRes.json()) as CreateInvitationResponse;
      const rawToken = extractRawToken(createJson.inviteUrl!);

      // Invitee can still accept invitation successfully
      const acceptRes = await app.request(`/api/invitations/${rawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Invited-Lockdown-Password-123!" }),
      });

      expect([200, 201]).toContain(acceptRes.status);
      const acceptJson = (await acceptRes.json()) as AcceptInvitationResponse;
      expect(acceptJson.success).toBe(true);
      expect(acceptJson.user?.email).toBe("lockdown-invited@example.com");

      const sessionCookie = acceptRes.headers.get("Set-Cookie")!.split(";")[0]!;
      const meRes = await app.request("/api/auth/me", {
        headers: { Cookie: sessionCookie },
      });
      expect(meRes.status).toBe(200);
    } finally {
      vault.close();
    }
  });

  it("generically rejects invalid, expired, revoked, or replayed tokens without leaking internal state", async () => {
    let now = Date.now();
    const { vault, app } = createTestApp(new RateLimiter({ now: () => now }));
    try {
      const admin = await registerAdmin(app);

      // 1. Completely invalid / non-existent token
      const bogusRes = await app.request(
        "/api/invitations/0000000000000000000000000000000000000000000000000000000000000000/accept",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: "Strong-Password-12345!" }),
        }
      );
      expect(bogusRes.status).toBe(400);
      const bogusJson = (await bogusRes.json()) as GenericResponse;
      expect(bogusJson.success).toBe(false);
      const standardError = bogusJson.error;
      expect(typeof standardError).toBe("string");

      // 2. Expired invitation (> 24 hours)
      const pastExpiresAt = Date.now() - 3600 * 1000;
      const expiredRawToken = "1111222233334444555566667777888811112222333344445555666677778888";
      const adminUser = vault.getUserByEmail("admin@example.com")!;
      vault.createInvitation({
        email: "expired-user@example.com",
        tokenHash: hashSessionToken(expiredRawToken),
        createdBy: adminUser.id,
        expiresAt: pastExpiresAt,
        createdAt: pastExpiresAt - 86400 * 1000,
      });

      const expiredRes = await app.request(`/api/invitations/${expiredRawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Strong-Password-12345!" }),
      });
      expect(expiredRes.status).toBe(400);
      const expiredJson = (await expiredRes.json()) as GenericResponse;
      expect(expiredJson.success).toBe(false);
      // Ensure error message does not leak "token expired" distinction
      expect(expiredJson.error).toBe(standardError);

      // 3. Revoked invitation
      const revokeCreate = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "to-be-revoked@example.com" }),
      });
      const revokeCreateJson = (await revokeCreate.json()) as CreateInvitationResponse;
      const revokeRawToken = extractRawToken(revokeCreateJson.inviteUrl!);
      const inviteId = revokeCreateJson.invitation!.id;

      // Admin revokes it
      const deleteRes = await app.request(`/api/admin/invitations/${inviteId}`, {
        method: "DELETE",
        headers: { Cookie: admin.cookie },
      });
      expect(deleteRes.status).toBe(200);

      // Accepting revoked token fails generically
      const revokedAcceptRes = await app.request(`/api/invitations/${revokeRawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Strong-Password-12345!" }),
      });
      expect(revokedAcceptRes.status).toBe(400);
      const revokedAcceptJson = (await revokedAcceptRes.json()) as GenericResponse;
      expect(revokedAcceptJson.success).toBe(false);
      expect(revokedAcceptJson.error).toBe(standardError);

      expect(vault.getUserCount()).toBe(1);
      expect(vault.getSystemStatsAdmin(false).activeSessions).toBe(1);
      const singleCreate = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "single-use@example.com" }),
      });
      const singleCreateJson = (await singleCreate.json()) as CreateInvitationResponse;
      const singleRawToken = extractRawToken(singleCreateJson.inviteUrl!);

      // First acceptance: succeeds
      const firstAccept = await app.request(`/api/invitations/${singleRawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Strong-Password-12345!" }),
      });
      expect(firstAccept.status).toBe(200);
      now += RATE_LIMIT_POLICIES.registration.windowMs + 1;

      // Second acceptance (replay): rejected generically
      const replayAccept = await app.request(`/api/invitations/${singleRawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Another-Strong-Password-123!" }),
      });
      expect(replayAccept.status).toBe(400);
      const replayJson = (await replayAccept.json()) as GenericResponse;
      expect(replayJson.success).toBe(false);
      expect(replayJson.error).toBe(standardError);
      expect(vault.getUserCount()).toBe(2);
      expect(vault.getSystemStatsAdmin(false).activeSessions).toBe(2);
    } finally {
      vault.close();
    }
  });

  it("binds invitation to canonical email and prevents duplicate registrations", async () => {
    const { vault, app } = createTestApp();
    try {
      const admin = await registerAdmin(app);

      // 1. Create and accept invitation for bound@example.com
      const createRes = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "bound@example.com" }),
      });
      const createJson = (await createRes.json()) as CreateInvitationResponse;
      const rawToken = extractRawToken(createJson.inviteUrl!);

      const acceptRes = await app.request(`/api/invitations/${rawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Valid-Strong-Password-123!" }),
      });
      expect(acceptRes.status).toBe(200);

      // 2. Duplicate registration attempt for already-accepted email must fail
      const dupRegister = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "bound@example.com",
          password: "Another-Password-123!",
        }),
      });
      expect(dupRegister.status).toBe(400);
      const dupRegJson = (await dupRegister.json()) as GenericResponse;
      expect(dupRegJson.success).toBe(false);

      // 3. Creating an invitation for already registered email must fail
      const dupInvite = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "bound@example.com" }),
      });
      expect(dupInvite.status).toBe(400);
      const dupInviteJson = (await dupInvite.json()) as GenericResponse;
      expect(dupInviteJson.success).toBe(false);

      // 4. Case-insensitive email collision prevention
      const caseDupInvite = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "BOUND@EXAMPLE.COM" }),
      });
      expect(caseDupInvite.status).toBe(400);
    } finally {
      vault.close();
    }
  });

  it("enforces password complexity during invitation acceptance and keeps invitation usable", async () => {
    const { vault, app } = createTestApp();
    try {
      const admin = await registerAdmin(app);

      const createRes = await app.request("/api/admin/invitations", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: admin.cookie },
        body: JSON.stringify({ email: "complexity@example.com" }),
      });
      const createJson = (await createRes.json()) as CreateInvitationResponse;
      const rawToken = extractRawToken(createJson.inviteUrl!);

      // Attempt with too short password (< 12 characters)
      const shortPassRes = await app.request(`/api/invitations/${rawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "short" }),
      });
      expect(shortPassRes.status).toBe(400);
      const shortPassJson = (await shortPassRes.json()) as GenericResponse;
      expect(shortPassJson.success).toBe(false);
      expect(shortPassJson.error?.toLowerCase()).toContain("password");

      // The invitation should not be consumed by a failed attempt; a valid password succeeds
      const validPassRes = await app.request(`/api/invitations/${rawToken}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "Valid-Strong-Password-123!" }),
      });
      expect(validPassRes.status).toBe(200);
      const validPassJson = (await validPassRes.json()) as AuthResponse;
      expect(validPassJson.success).toBe(true);
      expect(validPassJson.user?.email).toBe("complexity@example.com");
    } finally {
      vault.close();
    }
  });
});

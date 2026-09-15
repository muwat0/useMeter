import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { PollerEngine } from "../src/core/poller/poller";
import { createServer } from "../src/server/app";

interface RegisterResponse {
  success: boolean;
  user: {
    id: string;
    email: string;
  };
}

interface ErrorResponse {
  success: boolean;
  error: string;
}

interface UserListItem {
  id: string;
  email: string;
  role: string;
  credentialCount: number;
  activeSessionCount: number;
}

interface StatsResponse {
  success: boolean;
  data: {
    totalUsers: number;
    totalCredentials: number;
    totalSnapshots: number;
    activeSessions: number;
    pollerRunning: boolean;
    allowRegistration: boolean;
    databaseSizeBytes: number;
    integrity: boolean;
    providerCounts: Record<string, number>;
  };
}
interface SettingsResponse {
  success: boolean;
  allowRegistration: boolean;
  data?: {
    allowRegistration: boolean;
  };
}


describe("Admin Panel & Role-Based Access Control", () => {
  it("guards admin routes against unauthenticated and non-admin callers", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // 1. Unauthenticated requests
    const anonAdminHtml = await app.request("/admin");
    expect(anonAdminHtml.status).toBe(302);
    expect(anonAdminHtml.headers.get("Location")).toBe("/login");

    const anonAdminStats = await app.request("/api/admin/stats");
    expect(anonAdminStats.status).toBe(401);
    const anonStatsJson = (await anonAdminStats.json()) as ErrorResponse;
    expect(anonStatsJson.success).toBe(false);
    expect(anonStatsJson.error).toBe("Unauthorized");

    const anonAdminUsers = await app.request("/api/admin/users");
    expect(anonAdminUsers.status).toBe(401);

    // 2. Register first user (automatically becomes 'admin')
    const adminReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Admin-Password-123456" }),
    });
    expect(adminReg.status).toBe(201);

    // 3. Register second user (automatically becomes 'user')
    const userReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "bob@example.com", password: "Bob-Password-123456" }),
    });
    expect(userReg.status).toBe(201);
    const userCookie = userReg.headers.get("Set-Cookie")!.split(";")[0]!;

    // 4. Regular user receives 403 on GET /admin and GET /api/admin/stats
    const userAdminHtml = await app.request("/admin", {
      headers: { Cookie: userCookie },
    });
    expect(userAdminHtml.status).toBe(403);
    const userAdminHtmlText = await userAdminHtml.text();
    expect(userAdminHtmlText).toContain("403 - Erişim Yetkiniz Yok / Forbidden: Admin Access Required");

    const userAdminStats = await app.request("/api/admin/stats", {
      headers: { Cookie: userCookie },
    });
    expect(userAdminStats.status).toBe(403);
    const userStatsJson = (await userAdminStats.json()) as ErrorResponse;
    expect(userStatsJson.success).toBe(false);
    expect(userStatsJson.error).toBe("Admin access required");

    const userAdminUsers = await app.request("/api/admin/users", {
      headers: { Cookie: userCookie },
    });
    expect(userAdminUsers.status).toBe(403);

    // Regular user attempting PATCH /api/admin/users/:id/role is rejected with 403
    const userPatchRole = await app.request("/api/admin/users/fake-id/role", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: userCookie },
      body: JSON.stringify({ role: "admin" }),
    });
    expect(userPatchRole.status).toBe(403);

    // Regular user attempting DELETE /api/admin/users/:id is rejected with 403
    const userDelete = await app.request("/api/admin/users/fake-id", {
      method: "DELETE",
      headers: { Cookie: userCookie },
    });
    expect(userDelete.status).toBe(403);

    vault.close();
  });

  it("allows admin user to access dashboard, inspect stats, and view admin link on main dashboard", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register admin (1st user)
    const adminReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Admin-Password-123456" }),
    });
    const adminCookie = adminReg.headers.get("Set-Cookie")!.split(";")[0]!;

    // Register normal user (2nd user)
    const userReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "regular@example.com", password: "Regular-Password-123456" }),
    });
    const userCookie = userReg.headers.get("Set-Cookie")!.split(";")[0]!;

    // Admin receives 200 on /admin SSR page
    const adminHtmlRes = await app.request("/admin", {
      headers: { Cookie: adminCookie },
    });
    expect(adminHtmlRes.status).toBe(200);
    const adminHtml = await adminHtmlRes.text();
    expect(adminHtml).toContain("useMeter");
    expect(adminHtml).toContain("ADMIN");
    expect(adminHtml).toContain("Kullanıcı Yönetimi");
    expect(adminHtml).toContain("admin@example.com");
    expect(adminHtml).toContain("regular@example.com");

    // Admin receives 200 on /api/admin/stats with system telemetry
    const adminStatsRes = await app.request("/api/admin/stats", {
      headers: { Cookie: adminCookie },
    });
    expect(adminStatsRes.status).toBe(200);
    const statsJson = (await adminStatsRes.json()) as StatsResponse;
    expect(statsJson.success).toBe(true);
    expect(statsJson.data.totalUsers).toBe(2);
    expect(statsJson.data.activeSessions).toBe(2);
    expect(statsJson.data.integrity).toBe(true);
    expect(typeof statsJson.data.databaseSizeBytes).toBe("number");

    // Admin navigation is rendered by the React client from the sanitized bootstrap user role.
    const adminMainDash = await app.request("/", {
      headers: { Cookie: adminCookie },
    });
    expect(adminMainDash.status).toBe(200);
    const adminMainDashHtml = await adminMainDash.text();
    expect(adminMainDashHtml).toContain('id="usemeter-bootstrap"');
    expect(adminMainDashHtml).toContain('"role":"admin"');

    // Regular users receive a non-admin bootstrap role.
    const userMainDash = await app.request("/", {
      headers: { Cookie: userCookie },
    });
    expect(userMainDash.status).toBe(200);
    const userMainDashHtml = await userMainDash.text();
    expect(userMainDashHtml).toContain('id="usemeter-bootstrap"');
    expect(userMainDashHtml).toContain('"role":"user"');

    vault.close();
  });

  it("lists all users with statistics via GET /api/admin/users", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register admin (1st user)
    const adminReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Admin-Password-123456" }),
    });
    const adminCookie = adminReg.headers.get("Set-Cookie")!.split(";")[0]!;

    // Register user2
    await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user2@example.com", password: "User2-Password-123456" }),
    });

    const listRes = await app.request("/api/admin/users", {
      headers: { Cookie: adminCookie },
    });
    expect(listRes.status).toBe(200);
    const listJson = (await listRes.json()) as {
      success: boolean;
      data: UserListItem[];
    };
    expect(listJson.success).toBe(true);
    expect(listJson.data.length).toBe(2);

    const adminUser = listJson.data.find(u => u.email === "admin@example.com");
    expect(adminUser).toBeDefined();
    expect(adminUser?.role).toBe("admin");
    expect(adminUser?.activeSessionCount).toBeGreaterThanOrEqual(1);

    const regularUser = listJson.data.find(u => u.email === "user2@example.com");
    expect(regularUser).toBeDefined();
    expect(regularUser?.role).toBe("user");

    vault.close();
  });

  it("updates user role via PATCH /api/admin/users/:id/role with last admin safeguards", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register admin (1st user)
    const adminReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Admin-Password-123456" }),
    });
    const adminCookie = adminReg.headers.get("Set-Cookie")!.split(";")[0]!;
    const adminData = (await adminReg.json()) as RegisterResponse;
    const adminId = adminData.user.id;

    // Register target user (2nd user)
    const targetReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "target@example.com", password: "Target-Password-123456" }),
    });
    const targetData = (await targetReg.json()) as RegisterResponse;
    const targetId = targetData.user.id;

    // 1. Promote target to admin
    const promoteRes = await app.request(`/api/admin/users/${targetId}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ role: "admin" }),
    });
    expect(promoteRes.status).toBe(200);
    const promoteJson = (await promoteRes.json()) as { success: boolean };
    expect(promoteJson.success).toBe(true);

    // Verify target is now admin in list
    const listAfterPromote = await app.request("/api/admin/users", {
      headers: { Cookie: adminCookie },
    });
    const listAfterPromoteJson = (await listAfterPromote.json()) as { data: UserListItem[] };
    const usersAfterPromote = listAfterPromoteJson.data;
    expect(usersAfterPromote.find(u => u.id === targetId)?.role).toBe("admin");

    // 2. Demote target back to user (now allowed because admin@example.com is also admin)
    const demoteRes = await app.request(`/api/admin/users/${targetId}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ role: "user" }),
    });
    expect(demoteRes.status).toBe(200);

    // 3. Demoting the last admin returns 400 with descriptive error
    const demoteLastAdminRes = await app.request(`/api/admin/users/${adminId}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ role: "user" }),
    });
    expect(demoteLastAdminRes.status).toBe(400);
    const demoteLastJson = (await demoteLastAdminRes.json()) as ErrorResponse;
    expect(demoteLastJson.success).toBe(false);
    expect(demoteLastJson.error).toContain("Cannot demote the last admin");

    // 4. Invalid role payload returns 400
    const invalidRoleRes = await app.request(`/api/admin/users/${targetId}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ role: "superadmin" }),
    });
    expect(invalidRoleRes.status).toBe(400);

    vault.close();
  });

  it("deletes user via DELETE /api/admin/users/:id with self & last admin safeguards", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // Register admin (1st user)
    const adminReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Admin-Password-123456" }),
    });
    const adminCookie = adminReg.headers.get("Set-Cookie")!.split(";")[0]!;
    const adminData = (await adminReg.json()) as RegisterResponse;
    const adminId = adminData.user.id;

    // Register user to delete (2nd user)
    const bobReg = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "bob@example.com", password: "Bob-Password-123456" }),
    });
    const bobData = (await bobReg.json()) as RegisterResponse;
    const bobId = bobData.user.id;
    const bobCookie = bobReg.headers.get("Set-Cookie")!.split(";")[0]!;

    // Bob adds a credential
    await app.request("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: bobCookie },
      body: JSON.stringify({
        provider: "openrouter",
        accountLabel: "Bob Key",
        credentialType: "api_key",
        secret: "sk-or-v1-bob-secret-key",
      }),
    });

    // 1. Deleting self returns 400
    const deleteSelfRes = await app.request(`/api/admin/users/${adminId}`, {
      method: "DELETE",
      headers: { Cookie: adminCookie },
    });
    expect(deleteSelfRes.status).toBe(400);
    const deleteSelfJson = (await deleteSelfRes.json()) as ErrorResponse;
    expect(deleteSelfJson.success).toBe(false);
    expect(deleteSelfJson.error).toContain("Cannot delete your own account");

    // 2. Admin can delete Bob
    const deleteBobRes = await app.request(`/api/admin/users/${bobId}`, {
      method: "DELETE",
      headers: { Cookie: adminCookie },
    });
    expect(deleteBobRes.status).toBe(200);
    const deleteBobJson = (await deleteBobRes.json()) as { success: boolean };
    expect(deleteBobJson.success).toBe(true);

    // Bob is no longer in users list
    const usersAfterDelete = await app.request("/api/admin/users", {
      headers: { Cookie: adminCookie },
    });
    const usersAfterDeleteJson = (await usersAfterDelete.json()) as { data: UserListItem[] };
    const usersList = usersAfterDeleteJson.data;
    expect(usersList.find(u => u.id === bobId)).toBeUndefined();
    expect(usersList.length).toBe(1);

    // Bob's session is now invalid (cascaded delete)
    const bobMe = await app.request("/api/auth/me", {
      headers: { Cookie: bobCookie },
    });
    expect(bobMe.status).toBe(401);

    vault.close();
  });

  it("manages public registration policy via admin API and enforces registration restrictions", async () => {
    const vault = new StorageVault(":memory:");
    const registry = createDefaultRegistry();
    const poller = new PollerEngine(vault, registry);
    const app = createServer(vault, poller, registry);

    // 1. Zero users: GET /register is open even if setting is false in DB
    vault.setRegistrationAllowed(false);
    const initialRegPage = await app.request("/register");
    expect(initialRegPage.status).toBe(200);
    const initialRegHtml = await initialRegPage.text();
    expect(initialRegHtml).toContain("authForm");
    expect(initialRegHtml).toContain('data-i18n="authRegisterTitle"');
    expect(initialRegHtml).not.toContain('data-i18n="authRegDisabledTitle"');
    // First user registration always succeeds (admin bootstrap)
    const adminRegRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@example.com", password: "Password12345!" }),
    });
    expect(adminRegRes.status).toBe(201);
    const adminCookie = adminRegRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // 2. Second user registers while registration is allowed
    vault.setRegistrationAllowed(true);
    const userRegRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "Password12345!" }),
    });
    expect(userRegRes.status).toBe(201);
    const userCookie = userRegRes.headers.get("Set-Cookie")!.split(";")[0]!;

    // 3. Admin can get settings via GET /api/admin/settings
    const getSettingsRes = await app.request("/api/admin/settings", {
      headers: { Cookie: adminCookie },
    });
    expect(getSettingsRes.status).toBe(200);
    const getSettingsJson = (await getSettingsRes.json()) as SettingsResponse;
    expect(getSettingsJson.success).toBe(true);
    expect(getSettingsJson.allowRegistration).toBe(true);
    expect(getSettingsJson.data?.allowRegistration).toBe(true);

    // 4. Non-admin cannot get settings (403)
    const nonAdminGetRes = await app.request("/api/admin/settings", {
      headers: { Cookie: userCookie },
    });
    expect(nonAdminGetRes.status).toBe(403);

    // Non-admin cannot change settings (403)
    const nonAdminPatchRes = await app.request("/api/admin/settings/registration", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: userCookie },
      body: JSON.stringify({ allowRegistration: false }),
    });
    expect(nonAdminPatchRes.status).toBe(403);

    // 5. Unauthenticated callers are rejected with 401
    const unauthGetRes = await app.request("/api/admin/settings");
    expect(unauthGetRes.status).toBe(401);

    const unauthPatchRes = await app.request("/api/admin/settings/registration", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ allowRegistration: false }),
    });
    expect(unauthPatchRes.status).toBe(401);

    // 6. Admin can toggle registration off via PATCH /api/admin/settings/registration
    const patchOffRes = await app.request("/api/admin/settings/registration", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ allowRegistration: false }),
    });
    expect(patchOffRes.status).toBe(200);
    const patchOffJson = (await patchOffRes.json()) as SettingsResponse;
    expect(patchOffJson.success).toBe(true);
    expect(patchOffJson.allowRegistration).toBe(false);
    expect(patchOffJson.data?.allowRegistration).toBe(false);

    // Verify GET /api/admin/settings returns false
    const verifyGetSettingsRes = await app.request("/api/admin/settings", {
      headers: { Cookie: adminCookie },
    });
    const verifyGetSettingsJson = (await verifyGetSettingsRes.json()) as SettingsResponse;
    expect(verifyGetSettingsJson.allowRegistration).toBe(false);

    // 7. When toggled off, POST /api/auth/register returns 403 Forbidden
    const blockedRegRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "blocked@example.com", password: "Password12345!" }),
    });
    expect(blockedRegRes.status).toBe(403);
    const blockedRegJson = (await blockedRegRes.json()) as ErrorResponse;
    expect(blockedRegJson.success).toBe(false);
    expect(blockedRegJson.error).toBe("Registration is disabled by administrator");

    // 8. GET /register indicates registration is disabled with a link to /login
    const disabledRegPageRes = await app.request("/register");
    expect(disabledRegPageRes.status).toBe(200);
    const disabledRegHtml = await disabledRegPageRes.text();
    expect(disabledRegHtml).toContain("Registration is disabled by administrator");
    expect(disabledRegHtml).toContain("/login");
    expect(disabledRegHtml).toContain("Kayıtlar Kapalı");

    // Admin dashboard HTML shows Registration Policy card and toggle button
    const adminDashboardRes = await app.request("/admin", {
      headers: { Cookie: adminCookie },
    });
    expect(adminDashboardRes.status).toBe(200);
    const adminHtml = await adminDashboardRes.text();
    expect(adminHtml).toContain("Kayıt Politikası");
    expect(adminHtml).toContain("regToggleBtn");
    expect(adminHtml).toContain("Kapalı");

    // Invalid payload validation
    const invalidPayloadRes = await app.request("/api/admin/settings/registration", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ allowRegistration: "not-a-boolean" }),
    });
    expect(invalidPayloadRes.status).toBe(400);

    // 9. Admin can toggle registration back on; registration succeeds
    const patchOnRes = await app.request("/api/admin/settings/registration", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ allowRegistration: true }),
    });
    expect(patchOnRes.status).toBe(200);
    const patchOnJson = (await patchOnRes.json()) as SettingsResponse;
    expect(patchOnJson.success).toBe(true);
    expect(patchOnJson.allowRegistration).toBe(true);

    const successRegRes = await app.request("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "success@example.com", password: "Password12345!" }),
    });
    expect(successRegRes.status).toBe(201);
    const successRegJson = (await successRegRes.json()) as RegisterResponse;
    expect(successRegJson.success).toBe(true);
    expect(successRegJson.user.email).toBe("success@example.com");

    vault.close();
  });
});

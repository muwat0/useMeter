import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { AuthService } from "../src/core/auth/auth";
import { hashSessionToken } from "../src/core/crypto";

describe("Admin Invitation Onboarding & Security", () => {
  it("stores token hash only at rest and never persists raw token or exposes hash in views", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    // Bootstrap first user as admin
    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;
    expect(adminReg.data.user.role).toBe("admin");

    // Admin creates an invitation
    const inviteRes = await auth.createInvitation(adminId, "invitee@example.com");
    expect(inviteRes.success).toBe(true);
    if (!inviteRes.success) throw new Error("Invitation creation failed");

    const { invitation, token: rawToken } = inviteRes.data;

    // 1. Raw token is returned at creation (32 bytes hex = 64 characters)
    expect(typeof rawToken).toBe("string");
    expect(rawToken.length).toBe(64);

    // 2. InvitationView does not expose tokenHash or raw token
    expect(Reflect.has(invitation, "tokenHash")).toBe(false);
    expect(Reflect.has(invitation, "token")).toBe(false);
    expect(invitation.email).toBe("invitee@example.com");
    expect(invitation.status).toBe("pending");
    expect(invitation.createdBy).toBe(adminId);
    expect(invitation.acceptedAt).toBeNull();
    expect(invitation.revokedAt).toBeNull();
    expect(invitation.expiresAt).toBeGreaterThan(Date.now());

    // 3. Inspect raw SQLite database row directly
    const dbTokenHash = hashSessionToken(rawToken);
    const internalInvite = vault.getInvitationByTokenHash(dbTokenHash);
    expect(internalInvite).not.toBeNull();
    expect(internalInvite!.tokenHash).toBe(dbTokenHash);
    expect(internalInvite!.tokenHash).not.toBe(rawToken);

    // Also test through listing
    const listRes = await auth.listInvitations(adminId);
    expect(listRes.success).toBe(true);
    if (!listRes.success) throw new Error("List failed");
    expect(listRes.data.length).toBe(1);
    const firstInvite = listRes.data[0];
    expect(firstInvite).toBeDefined();
    expect(Reflect.has(firstInvite!, "tokenHash")).toBe(false);
    expect(Reflect.has(firstInvite!, "token")).toBe(false);

    vault.close();
  });

  it("enforces admin-only creation, listing, and revocation", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    // First user is admin
    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    // Second user is regular user
    const userReg = await auth.register("regular@example.com", "Regular-User-Password-123!");
    expect(userReg.success).toBe(true);
    if (!userReg.success) throw new Error("User registration failed");
    const regularId = userReg.data.user.id;
    expect(userReg.data.user.role).toBe("user");

    // Regular user cannot create invitation
    const nonAdminCreate = await auth.createInvitation(regularId, "target@example.com");
    expect(nonAdminCreate.success).toBe(false);
    if (!nonAdminCreate.success) {
      expect(nonAdminCreate.error).toBe("FORBIDDEN");
    }

    // Regular user cannot list invitations
    const nonAdminList = await auth.listInvitations(regularId);
    expect(nonAdminList.success).toBe(false);
    if (!nonAdminList.success) {
      expect(nonAdminList.error).toBe("FORBIDDEN");
    }

    // Admin creates invitation
    const adminCreate = await auth.createInvitation(adminId, "target@example.com");
    expect(adminCreate.success).toBe(true);
    if (!adminCreate.success) throw new Error("Create failed");
    const invitationId = adminCreate.data.invitation.id;

    // Regular user cannot revoke invitation
    const nonAdminRevoke = await auth.revokeInvitation(regularId, invitationId);
    expect(nonAdminRevoke.success).toBe(false);
    if (!nonAdminRevoke.success) {
      expect(nonAdminRevoke.error).toBe("FORBIDDEN");
    }

    // Admin can revoke invitation
    const adminRevoke = await auth.revokeInvitation(adminId, invitationId);
    expect(adminRevoke.success).toBe(true);
    if (!adminRevoke.success) throw new Error("Revoke failed");
    expect(adminRevoke.data).toBe(true);

    vault.close();
  });

  it("allows acceptance, binds canonical email, assigns role 'user', and issues 30-day session", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    // Create invitation with mixed-case email
    const createRes = await auth.createInvitation(adminId, "  NewUser.Invited@Example.COM  ");
    expect(createRes.success).toBe(true);
    if (!createRes.success) throw new Error("Create failed");
    expect(createRes.data.invitation.email).toBe("newuser.invited@example.com");

    const rawToken = createRes.data.token;

    // Accept invitation with strong password
    const acceptRes = await auth.acceptInvitation(rawToken, "NewUser-Secure-Password-789!");
    expect(acceptRes.success).toBe(true);
    if (!acceptRes.success) throw new Error("Accept failed");

    const { user, token: sessionToken, session } = acceptRes.data;

    // Role MUST be "user"
    expect(user.role).toBe("user");
    expect(user.email).toBe("newuser.invited@example.com");

    // Session is valid and issued for 30 days
    expect(typeof sessionToken).toBe("string");
    expect(session.userId).toBe(user.id);
    expect(session.expiresAt).toBeGreaterThan(Date.now() + 29 * 24 * 60 * 60 * 1000);

    // User can authenticate with issued session token
    const authCheck = await auth.authenticate(sessionToken);
    expect(authCheck.success).toBe(true);
    if (authCheck.success) {
      expect(authCheck.data.id).toBe(user.id);
      expect(authCheck.data.role).toBe("user");
    }

    // User can log in with new password
    const loginRes = await auth.login("newuser.invited@example.com", "NewUser-Secure-Password-789!");
    expect(loginRes.success).toBe(true);

    vault.close();
  });

  it("enforces single-use and prevents replay attacks", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    const createRes = await auth.createInvitation(adminId, "singleuse@example.com");
    expect(createRes.success).toBe(true);
    if (!createRes.success) throw new Error("Create failed");
    const rawToken = createRes.data.token;

    // First acceptance succeeds
    const firstAccept = await auth.acceptInvitation(rawToken, "Valid-Strong-Password-123!");
    expect(firstAccept.success).toBe(true);

    // Replay acceptance with same token fails generically
    const replayAccept = await auth.acceptInvitation(rawToken, "Another-Strong-Password-456!");
    expect(replayAccept.success).toBe(false);
    if (!replayAccept.success) {
      expect(replayAccept.error).toBe("INVALID_INVITATION");
    }

    vault.close();
  });

  it("rejects revoked invitations", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    const createRes = await auth.createInvitation(adminId, "revoked@example.com");
    expect(createRes.success).toBe(true);
    if (!createRes.success) throw new Error("Create failed");
    const { token: rawToken, invitation } = createRes.data;

    // Admin revokes the invitation
    const revokeRes = await auth.revokeInvitation(adminId, invitation.id);
    expect(revokeRes.success).toBe(true);

    // Attempt to accept revoked invitation fails
    const acceptRes = await auth.acceptInvitation(rawToken, "Valid-Strong-Password-123!");
    expect(acceptRes.success).toBe(false);
    if (!acceptRes.success) {
      expect(acceptRes.error).toBe("INVALID_INVITATION");
    }

    vault.close();
  });

  it("rejects expired invitations (> 24 hours)", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    // Create an invitation that expired 1 hour ago
    const pastExpiresAt = Date.now() - 60 * 60 * 1000;
    const rawToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const tokenHash = hashSessionToken(rawToken);

    vault.createInvitation({
      email: "expired@example.com",
      tokenHash,
      createdBy: adminId,
      expiresAt: pastExpiresAt,
      createdAt: pastExpiresAt - 24 * 60 * 60 * 1000,
    });

    // Check status in view
    const listRes = await auth.listInvitations(adminId);
    expect(listRes.success).toBe(true);
    if (listRes.success) {
      const expiredInvite = listRes.data.find((i) => i.email === "expired@example.com");
      expect(expiredInvite).toBeDefined();
      expect(expiredInvite!.status).toBe("expired");
    }

    // Acceptance fails with generic invalid token error
    const acceptRes = await auth.acceptInvitation(rawToken, "Valid-Strong-Password-123!");
    expect(acceptRes.success).toBe(false);
    if (!acceptRes.success) {
      expect(acceptRes.error).toBe("INVALID_INVITATION");
    }

    vault.close();
  });

  it("allows invitation acceptance when public registration is closed", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    // Turn OFF public registration
    vault.setRegistrationAllowed(false);
    expect(vault.isRegistrationAllowed()).toBe(false);

    // Admin creates invitation
    const createRes = await auth.createInvitation(adminId, "invited-during-lockdown@example.com");
    expect(createRes.success).toBe(true);
    if (!createRes.success) throw new Error("Create failed");
    const rawToken = createRes.data.token;

    // Accepting invitation succeeds despite public registration being closed
    const acceptRes = await auth.acceptInvitation(rawToken, "Lockdown-Invited-Password-123!");
    expect(acceptRes.success).toBe(true);
    if (!acceptRes.success) throw new Error("Accept should succeed when registration is closed");

    expect(acceptRes.data.user.email).toBe("invited-during-lockdown@example.com");
    expect(acceptRes.data.user.role).toBe("user");

    vault.close();
  });

  it("prevents creating invitation for existing user or accepting when email was taken", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    // Cannot invite existing user
    const duplicateInvite = await auth.createInvitation(adminId, "admin@example.com");
    expect(duplicateInvite.success).toBe(false);
    if (!duplicateInvite.success) {
      expect(duplicateInvite.error).toBe("EMAIL_EXISTS");
    }

    // Case-insensitive duplicate check
    const caseDupInvite = await auth.createInvitation(adminId, "ADMIN@EXAMPLE.COM");
    expect(caseDupInvite.success).toBe(false);
    if (!caseDupInvite.success) {
      expect(caseDupInvite.error).toBe("EMAIL_EXISTS");
    }

    vault.close();
  });

  it("does not claim unowned legacy credentials upon invitation acceptance", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    // Bootstrap first user as admin (which claims initial legacy data)
    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    // Admin adds a credential
    vault.saveCredential(adminId, {
      provider: "anthropic",
      accountLabel: "Admin Account",
      credentialType: "api_key",
      secret: "sk-ant-test-key",
    });
    const inviteRes = await auth.createInvitation(adminId, "isolated@example.com");
    expect(inviteRes.success).toBe(true);
    if (!inviteRes.success) throw new Error("Create failed");

    const acceptRes = await auth.acceptInvitation(inviteRes.data.token, "Isolated-Password-123!");
    expect(acceptRes.success).toBe(true);
    if (!acceptRes.success) throw new Error("Accept failed");

    // The invited user has role "user" and 0 credentials
    expect(acceptRes.data.user.role).toBe("user");
    const userCreds = vault.listCredentials(acceptRes.data.user.id);
    expect(userCreds.length).toBe(0);

    vault.close();
  });

  it("enforces password complexity during invitation acceptance and keeps invitation usable", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);

    const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
    expect(adminReg.success).toBe(true);
    if (!adminReg.success) throw new Error("Admin registration failed");
    const adminId = adminReg.data.user.id;

    const inviteRes = await auth.createInvitation(adminId, "passwordtest@example.com");
    expect(inviteRes.success).toBe(true);
    if (!inviteRes.success) throw new Error("Create failed");
    const rawToken = inviteRes.data.token;

    // 1. Weak password: < 12 characters
    const weakRes = await auth.acceptInvitation(rawToken, "short");
    expect(weakRes.success).toBe(false);
    if (!weakRes.success) {
      expect(weakRes.error).toBe("WEAK_PASSWORD");
    }

    // 2. Invitation was NOT consumed by failed attempt
    const validRes = await auth.acceptInvitation(rawToken, "Valid-Strong-Password-123!");
    expect(validRes.success).toBe(true);

    vault.close();
  });
  it("rejects unusable invitations before password hashing and creates no user or session", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);
    const originalHash = Bun.password.hash;
    let hashCalls = 0;

    try {
      const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
      if (!adminReg.success) throw new Error("Admin registration failed");
      const inviteRes = await auth.createInvitation(adminReg.data.user.id, "fast-check@example.com");
      if (!inviteRes.success) throw new Error("Invitation creation failed");
      const revokeRes = await auth.revokeInvitation(adminReg.data.user.id, inviteRes.data.invitation.id);
      expect(revokeRes.success).toBe(true);
      const sessionsBefore = vault.getSystemStatsAdmin(false).activeSessions;

      Bun.password.hash = async () => {
        hashCalls += 1;
        return "unused";
      };
      const result = await auth.acceptInvitation(inviteRes.data.token, "Valid-Strong-Password-123!");

      expect(result).toEqual({
        success: false,
        error: "INVALID_INVITATION",
        message: "Invalid, expired, or revoked invitation",
      });
      expect(hashCalls).toBe(0);
      expect(vault.getUserCount()).toBe(1);
      expect(vault.getSystemStatsAdmin(false).activeSessions).toBe(sessionsBefore);
    } finally {
      Bun.password.hash = originalHash;
      vault.close();
    }
  });

  it("allows exactly one concurrent acceptance and issues its session", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);
    try {
      const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
      if (!adminReg.success) throw new Error("Admin registration failed");
      const inviteRes = await auth.createInvitation(adminReg.data.user.id, "concurrent@example.com");
      if (!inviteRes.success) throw new Error("Invitation creation failed");
      const sessionsBefore = vault.getSystemStatsAdmin(false).activeSessions;

      const results = await Promise.all([
        auth.acceptInvitation(inviteRes.data.token, "First-Strong-Password-123!"),
        auth.acceptInvitation(inviteRes.data.token, "Second-Strong-Password-123!"),
      ]);
      const accepted = results.filter(result => result.success);
      const rejected = results.filter(result => !result.success);

      expect(accepted).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      if (accepted[0]?.success) {
        expect(accepted[0].data.user.email).toBe("concurrent@example.com");
        expect(accepted[0].data.user.role).toBe("user");
        expect((await auth.authenticate(accepted[0].data.token)).success).toBe(true);
      }
      expect(vault.getUserCount()).toBe(2);
      expect(vault.getSystemStatsAdmin(false).activeSessions).toBe(sessionsBefore + 1);
    } finally {
      vault.close();
    }
  });

  it("rejects revocation between the invitation precheck and atomic account creation", async () => {
    const vault = new StorageVault(":memory:");
    const auth = new AuthService(vault);
    try {
      const adminReg = await auth.register("admin@example.com", "Admin-Strong-Password-123!");
      if (!adminReg.success) throw new Error("Admin registration failed");
      const inviteRes = await auth.createInvitation(adminReg.data.user.id, "race@example.com");
      if (!inviteRes.success) throw new Error("Invitation creation failed");
      const sessionsBefore = vault.getSystemStatsAdmin(false).activeSessions;

      const acceptAtomic = vault.acceptInvitationAtomic.bind(vault);
      vault.acceptInvitationAtomic = ((tokenHash, userToCreate) => {
        const revoked = vault.revokeInvitation(adminReg.data.user.id, inviteRes.data.invitation.id);
        expect(revoked).toBe(true);
        return acceptAtomic(tokenHash, userToCreate);
      }) as typeof vault.acceptInvitationAtomic;

      const result = await auth.acceptInvitation(inviteRes.data.token, "Valid-Strong-Password-123!");
      expect(result).toMatchObject({
        success: false,
        error: "INVALID_INVITATION",
        message: "Invalid, expired, or revoked invitation",
      });
      expect(vault.getUserCount()).toBe(1);
      expect(vault.getSystemStatsAdmin(false).activeSessions).toBe(sessionsBefore);
    } finally {
      vault.close();
    }
  });
});

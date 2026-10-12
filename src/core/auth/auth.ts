import type { AuthResult, AuthSuccess, CreateInvitationResult, InvitationView, User } from "../../types";
import { generateSessionToken, hashPassword, hashSessionToken, verifyPassword } from "../crypto";
import type { StorageVault } from "../storage/vault";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const INVITATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Precomputed valid Argon2id hash for constant-time evaluation when email is unknown
const DUMMY_TIMING_HASH =
  "$argon2id$v=19$m=65536,t=2,p=1$pFiheG3pfmVEd4SrEZKdKOlIJn38dcPGFMyIMLn3ybM$xG5hE/QX0uFuIeCHaKDouy4FbynF+pJF/0XaNTFYcvM";

export class AuthService {
  readonly #vault: StorageVault;

  constructor(vault: StorageVault) {
    this.#vault = vault;
  }

  /**
   * Registers a new user identity, claims legacy data if this is the first non-system user,
   * and issues a 30-day session token.
   */
  async register(email: string, password: string): Promise<AuthResult<AuthSuccess>> {
    if (typeof email !== "string" || !email.trim()) {
      return { success: false, error: "INVALID_EMAIL", message: "Email address is required" };
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return { success: false, error: "INVALID_EMAIL", message: "Invalid email address format" };
    }

    if (typeof password !== "string") {
      return { success: false, error: "WEAK_PASSWORD", message: "Password must be a string" };
    }

    const charCount = Array.from(password).length;
    const byteLength = Buffer.byteLength(password, "utf8");

    if (charCount < 12 || password.length < 12) {
      return {
        success: false,
        error: "WEAK_PASSWORD",
        message: "Password must be at least 12 characters long",
      };
    }

    if (charCount > 256 || password.length > 256 || byteLength > 256) {
      return {
        success: false,
        error: "WEAK_PASSWORD",
        message: "Password must not exceed 256 UTF-8 characters/code units",
      };
    }

    const existing = this.#vault.getUserByEmail(normalizedEmail);
    if (existing) {
      return {
        success: false,
        error: "EMAIL_EXISTS",
        message: "An account with this email address already exists",
      };
    }

    const passwordHash = await hashPassword(password);
    let user: User;
    try {
      const created = this.#vault.createUserWithLegacyClaim(normalizedEmail, passwordHash);
      user = created.user;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("UNIQUE constraint failed: users.email")) {
        return {
          success: false,
          error: "EMAIL_EXISTS",
          message: "An account with this email address already exists",
        };
      }
      throw err;
    }

    const rawToken = generateSessionToken();
    const tokenHash = hashSessionToken(rawToken);
    const expiresAt = Date.now() + SESSION_TTL_MS;
    const session = this.#vault.createSession(user.id, tokenHash, expiresAt);

    return {
      success: true,
      data: {
        user,
        token: rawToken,
        session,
      },
    };
  }

  /**
   * Authenticates user credentials without leaking email existence through timing or error text.
   * On success, issues a 30-day session token.
   */
  async login(email: string, password: string): Promise<AuthResult<AuthSuccess>> {
    if (typeof email !== "string" || typeof password !== "string") {
      return {
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Invalid email or password",
      };
    }

    const normalizedEmail = email.trim().toLowerCase();
    const userWithHash = this.#vault.getUserByEmail(normalizedEmail);

    if (!userWithHash) {
      // Execute timing anchor to prevent user enumeration attacks via response latency
      await verifyPassword(password, DUMMY_TIMING_HASH);
      return {
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Invalid email or password",
      };
    }

    const isValidPassword = await verifyPassword(password, userWithHash.passwordHash);
    if (!isValidPassword) {
      return {
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Invalid email or password",
      };
    }

    const rawToken = generateSessionToken();
    const tokenHash = hashSessionToken(rawToken);
    const expiresAt = Date.now() + SESSION_TTL_MS;
    const session = this.#vault.createSession(userWithHash.id, tokenHash, expiresAt);

    return {
      success: true,
      data: {
        user: {
          id: userWithHash.id,
          email: userWithHash.email,
          role: userWithHash.role,
          createdAt: userWithHash.createdAt,
          updatedAt: userWithHash.updatedAt,
        },
        token: rawToken,
        session,
      },
    };
  }

  /**
   * Validates an opaque session token against the stored SHA-256 hash.
   * Lazily evicts expired sessions.
   */
  async authenticate(token: string): Promise<AuthResult<User>> {
    if (typeof token !== "string" || !token.trim()) {
      return {
        success: false,
        error: "UNAUTHENTICATED",
        message: "Session token is required",
      };
    }

    const tokenHash = hashSessionToken(token);
    this.#vault.deleteExpiredSessions();

    const sessionWithUser = this.#vault.getSessionByTokenHash(tokenHash);
    if (!sessionWithUser) {
      return {
        success: false,
        error: "UNAUTHENTICATED",
        message: "Invalid or expired session",
      };
    }

    if (sessionWithUser.expiresAt <= Date.now()) {
      this.#vault.deleteSessionByTokenHash(tokenHash);
      return {
        success: false,
        error: "UNAUTHENTICATED",
        message: "Session has expired",
      };
    }

    return {
      success: true,
      data: sessionWithUser.user,
    };
  }

  /**
   * Invalidates a session by deleting its hashed token.
   */
  async logout(token: string): Promise<void> {
    if (typeof token !== "string" || !token.trim()) return;
    const tokenHash = hashSessionToken(token);
    this.#vault.deleteSessionByTokenHash(tokenHash);
  }

  /**
   * Creates an admin-scoped single-use invitation bound to a canonical email.
   * Returns the raw 32-byte hex token only once upon creation; the SHA-256 hash is stored at rest.
   */
  async createInvitation(adminId: string, email: string): Promise<AuthResult<CreateInvitationResult>> {
    if (typeof adminId !== "string" || !adminId.trim()) {
      return {
        success: false,
        error: "FORBIDDEN",
        message: "Only administrators can create invitations",
      };
    }

    const admin = this.#vault.getUserById(adminId);
    if (!admin || admin.role !== "admin") {
      return {
        success: false,
        error: "FORBIDDEN",
        message: "Only administrators can create invitations",
      };
    }

    if (typeof email !== "string" || !email.trim()) {
      return {
        success: false,
        error: "INVALID_EMAIL",
        message: "Email address is required",
      };
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return {
        success: false,
        error: "INVALID_EMAIL",
        message: "Invalid email address format",
      };
    }

    const existingUser = this.#vault.getUserByEmail(normalizedEmail);
    if (existingUser) {
      return {
        success: false,
        error: "EMAIL_EXISTS",
        message: "An account with this email address already exists",
      };
    }

    const rawToken = generateSessionToken();
    const tokenHash = hashSessionToken(rawToken);
    const expiresAt = Date.now() + INVITATION_TTL_MS;

    try {
      const invitation = this.#vault.createInvitation({
        email: normalizedEmail,
        tokenHash,
        createdBy: adminId,
        expiresAt,
      });

      const invitationView: InvitationView = {
        id: invitation.id,
        email: invitation.email,
        createdBy: invitation.createdBy,
        status: "pending",
        expiresAt: invitation.expiresAt,
        acceptedAt: null,
        revokedAt: null,
        createdAt: invitation.createdAt,
      };

      return {
        success: true,
        data: {
          invitation: invitationView,
          token: rawToken,
        },
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("Unauthorized")) {
        return {
          success: false,
          error: "FORBIDDEN",
          message: "Only administrators can create invitations",
        };
      }
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: "Failed to create invitation",
      };
    }
  }

  /**
   * Accepts an invitation atomically using a raw token, hashes the password outside the transaction,
   * creates a normal user (role: 'user'), marks the invitation used, and issues a 30-day session.
   * Preserves generic invalid-token behavior on replay, expiration, revocation, or unknown token.
   * Operates independently of the public registration policy.
   */
  async acceptInvitation(rawToken: string, password: string): Promise<AuthResult<AuthSuccess>> {
    if (typeof rawToken !== "string" || !rawToken.trim()) {
      return {
        success: false,
        error: "INVALID_INVITATION",
        message: "Invalid, expired, or revoked invitation",
      };
    }

    if (typeof password !== "string") {
      return {
        success: false,
        error: "WEAK_PASSWORD",
        message: "Password must be a string",
      };
    }

    const charCount = Array.from(password).length;
    const byteLength = Buffer.byteLength(password, "utf8");

    if (charCount < 12 || password.length < 12) {
      return {
        success: false,
        error: "WEAK_PASSWORD",
        message: "Password must be at least 12 characters long",
      };
    }

    if (charCount > 256 || password.length > 256 || byteLength > 256) {
      return {
        success: false,
        error: "WEAK_PASSWORD",
        message: "Password must not exceed 256 UTF-8 characters/code units",
      };
    }

    const tokenHash = hashSessionToken(rawToken.trim());
    const invitation = this.#vault.getInvitationByTokenHash(tokenHash);
    if (
      !invitation ||
      invitation.acceptedAt !== null ||
      invitation.revokedAt !== null ||
      invitation.expiresAt <= Date.now()
    ) {
      return {
        success: false,
        error: "INVALID_INVITATION",
        message: "Invalid, expired, or revoked invitation",
      };
    }

    const passwordHash = await hashPassword(password);

    let user: User;
    try {
      const result = this.#vault.acceptInvitationAtomic(tokenHash, { passwordHash });
      user = result.user;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("EMAIL_EXISTS") || message.includes("UNIQUE constraint failed: users.email")) {
        return {
          success: false,
          error: "EMAIL_EXISTS",
          message: "An account with this email address already exists",
        };
      }
      return {
        success: false,
        error: "INVALID_INVITATION",
        message: "Invalid, expired, or revoked invitation",
      };
    }

    const sessionRawToken = generateSessionToken();
    const sessionTokenHash = hashSessionToken(sessionRawToken);
    const expiresAt = Date.now() + SESSION_TTL_MS;
    const session = this.#vault.createSession(user.id, sessionTokenHash, expiresAt);

    return {
      success: true,
      data: {
        user,
        token: sessionRawToken,
        session,
      },
    };
  }

  /**
   * Lists all invitations for an administrator without exposing token hashes.
   */
  async listInvitations(adminId: string): Promise<AuthResult<InvitationView[]>> {
    const admin = this.#vault.getUserById(adminId);
    if (!admin || admin.role !== "admin") {
      return {
        success: false,
        error: "FORBIDDEN",
        message: "Only administrators can view invitations",
      };
    }

    try {
      const invitations = this.#vault.listInvitations(adminId);
      return {
        success: true,
        data: invitations,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("Unauthorized")) {
        return {
          success: false,
          error: "FORBIDDEN",
          message: "Only administrators can view invitations",
        };
      }
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: "Failed to list invitations",
      };
    }
  }

  /**
   * Revokes an existing invitation by administrator ID and invitation ID.
   */
  async revokeInvitation(adminId: string, invitationId: string): Promise<AuthResult<boolean>> {
    const admin = this.#vault.getUserById(adminId);
    if (!admin || admin.role !== "admin") {
      return {
        success: false,
        error: "FORBIDDEN",
        message: "Only administrators can revoke invitations",
      };
    }

    if (typeof invitationId !== "string" || !invitationId.trim()) {
      return {
        success: false,
        error: "INVALID_INVITATION",
        message: "Invitation ID is required",
      };
    }

    try {
      const revoked = this.#vault.revokeInvitation(adminId, invitationId);
      return {
        success: true,
        data: revoked,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("Unauthorized")) {
        return {
          success: false,
          error: "FORBIDDEN",
          message: "Only administrators can revoke invitations",
        };
      }
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: "Failed to revoke invitation",
      };
    }
  }
}

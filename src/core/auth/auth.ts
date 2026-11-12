import { randomBytes } from "node:crypto";
import type {
  AuthResult,
  AuthSuccess,
  CreateInvitationResult,
  CreatePersonalAccessTokenResult,
  InvitationView,
  PersonalAccessToken,
  PersonalAccessTokenView,
  User,
} from "../../types";
import {
  formatTokenPrefix,
  generatePersonalAccessToken,
  generateSessionToken,
  hashPassword,
  hashPersonalAccessToken,
  hashSessionToken,
  verifyPassword,
} from "../crypto";
import type { StorageVault } from "../storage/vault";
import type { PasswordResetMailer } from "./password-reset-mailer";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const INVITATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const PASSWORD_RESET_TTL_MS = 15 * 60 * 1000;
const RECOVERY_MAX_ACTIVE = 2;
const RECOVERY_MAX_PENDING = 32;
const RECOVERY_QUEUE_TTL_MS = 30_000;
const RECOVERY_MAIL_TIMEOUT_MS = 5_000;

// Precomputed valid Argon2id hash for constant-time evaluation when email is unknown
const DUMMY_TIMING_HASH =
  "$argon2id$v=19$m=65536,t=2,p=1$pFiheG3pfmVEd4SrEZKdKOlIJn38dcPGFMyIMLn3ybM$xG5hE/QX0uFuIeCHaKDouy4FbynF+pJF/0XaNTFYcvM";

interface AuthServiceOptions {
  passwordResetMailer?: PasswordResetMailer;
  now?: () => number;
}

interface RecoveryQueueItem {
  email: string;
  expiresAt: number;
}

type PasswordValidation =
  | { success: true; password: string }
  | { success: false; message: string };

function validatePassword(password: unknown): PasswordValidation {
  if (typeof password !== "string") {
    return { success: false, message: "Password must be a string" };
  }

  const charCount = Array.from(password).length;
  const byteLength = Buffer.byteLength(password, "utf8");
  if (charCount < 12 || password.length < 12) {
    return { success: false, message: "Password must be at least 12 characters long" };
  }
  if (charCount > 256 || password.length > 256 || byteLength > 256) {
    return { success: false, message: "Password must not exceed 256 UTF-8 characters/code units" };
  }
  return { success: true, password };
}

function invalidPasswordResult(message: string): AuthResult<never> {
  return { success: false, error: "WEAK_PASSWORD", message };
}

export class AuthService {
  readonly #vault: StorageVault;
  readonly #passwordResetMailer?: PasswordResetMailer;
  readonly #now: () => number;
  readonly #recoveryQueue: RecoveryQueueItem[] = [];
  readonly #recoveryControllers = new Set<AbortController>();
  readonly #recoveryTasks = new Set<Promise<void>>();
  #recoveryActive = 0;
  #recoveryOutstandingSends = 0;
  #recoveryPump?: ReturnType<typeof setImmediate>;
  #recoveryExpiryTimer?: ReturnType<typeof setTimeout>;
  #recoveryStopped = false;

  constructor(vault: StorageVault, options: AuthServiceOptions = {}) {
    this.#vault = vault;
    this.#passwordResetMailer = options.passwordResetMailer;
    this.#now = options.now ?? Date.now;
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

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.success) return invalidPasswordResult(passwordValidation.message);
    const validPassword = passwordValidation.password;

    const existing = this.#vault.getUserByEmail(normalizedEmail);
    if (existing) {
      return {
        success: false,
        error: "EMAIL_EXISTS",
        message: "An account with this email address already exists",
      };
    }

    const passwordHash = await hashPassword(validPassword);
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
    const session = this.#vault.createSessionIfPasswordHashMatches(
      userWithHash.id,
      userWithHash.passwordHash,
      tokenHash,
      expiresAt,
    );
    if (!session) {
      return {
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Invalid email or password",
      };
    }

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

  isSessionActive(userId: string, rawToken: string): boolean {
    if (typeof rawToken !== "string" || !rawToken) return false;
    return this.isSessionTokenHashActive(userId, hashSessionToken(rawToken));
  }

  isSessionTokenHashActive(userId: string, tokenHash: string): boolean {
    const session = this.#vault.getSessionByTokenHash(tokenHash);
    return !!session && session.userId === userId && session.expiresAt > this.#now();
  }

  async changePassword(
    userId: string,
    rawSessionToken: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<AuthResult<void>> {
    const validation = validatePassword(newPassword);
    if (!validation.success) return invalidPasswordResult(validation.message);
    const currentValidation = validatePassword(currentPassword);
    if (!currentValidation.success) {
      return { success: false, error: "INVALID_CREDENTIALS", message: "Current password is incorrect" };
    }

    const sessionTokenHash = hashSessionToken(rawSessionToken);
    const user = this.#vault.getUserByIdWithPasswordHash(userId);
    if (!user || !this.isSessionTokenHashActive(userId, sessionTokenHash)) {
      return { success: false, error: "UNAUTHENTICATED", message: "Session is no longer active" };
    }
    if (!await verifyPassword(currentPassword, user.passwordHash)) {
      return { success: false, error: "INVALID_CREDENTIALS", message: "Current password is incorrect" };
    }

    const nextPasswordHash = await hashPassword(validation.password);
    const result = this.#vault.changePasswordAtomic(
      userId,
      sessionTokenHash,
      user.passwordHash,
      nextPasswordHash,
      this.#now(),
    );
    if (result === "unauthenticated") {
      return { success: false, error: "UNAUTHENTICATED", message: "Session is no longer active" };
    }
    if (result === "conflict") {
      return { success: false, error: "INVALID_CREDENTIALS", message: "Password changed during this request" };
    }
    return { success: true, data: undefined };
  }

  requestPasswordReset(email: string): AuthResult<void> {
    if (!this.#passwordResetMailer || this.#recoveryStopped || this.#recoveryQueue.length >= RECOVERY_MAX_PENDING) {
      return {
        success: false,
        error: "RECOVERY_UNAVAILABLE",
        message: "Password recovery is temporarily unavailable",
      };
    }
    if (typeof email !== "string" || email.trim().length > 320) {
      return { success: false, error: "INVALID_EMAIL", message: "Invalid email address format" };
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return { success: false, error: "INVALID_EMAIL", message: "Invalid email address format" };
    }

    this.#recoveryQueue.push({
      email: normalizedEmail,
      expiresAt: this.#now() + RECOVERY_QUEUE_TTL_MS,
    });
    this.#scheduleRecoveryExpiry();
    this.#scheduleRecoveryPump();
    return { success: true, data: undefined };
  }

  isPasswordRecoveryConfigured(): boolean {
    return this.#passwordResetMailer !== undefined && !this.#recoveryStopped;
  }

  async confirmPasswordReset(
    rawToken: string,
    newPassword: string,
  ): Promise<AuthResult<{ userId: string }>> {
    if (typeof rawToken !== "string" || !/^[0-9a-f]{64}$/i.test(rawToken)) {
      return { success: false, error: "INVALID_RESET_TOKEN", message: "Invalid or expired password reset link" };
    }
    const validation = validatePassword(newPassword);
    if (!validation.success) return invalidPasswordResult(validation.message);

    const tokenHash = hashSessionToken(rawToken);
    const reset = this.#vault.getPasswordResetContext(tokenHash, this.#now());
    if (!reset) {
      return { success: false, error: "INVALID_RESET_TOKEN", message: "Invalid or expired password reset link" };
    }
    const nextPasswordHash = await hashPassword(validation.password);
    const userId = this.#vault.consumePasswordResetToken(
      tokenHash,
      reset.passwordHash,
      nextPasswordHash,
      this.#now(),
    );
    if (!userId) {
      return { success: false, error: "INVALID_RESET_TOKEN", message: "Invalid or expired password reset link" };
    }
    return { success: true, data: { userId } };
  }

  async deleteAccount(
    userId: string,
    rawSessionToken: string,
    password: string,
  ): Promise<AuthResult<void>> {
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.success) {
      return { success: false, error: "INVALID_CREDENTIALS", message: "Password is incorrect" };
    }
    const sessionTokenHash = hashSessionToken(rawSessionToken);
    const user = this.#vault.getUserByIdWithPasswordHash(userId);
    if (!user || !this.isSessionTokenHashActive(userId, sessionTokenHash)) {
      return { success: false, error: "UNAUTHENTICATED", message: "Session is no longer active" };
    }
    if (!await verifyPassword(password, user.passwordHash)) {
      return { success: false, error: "INVALID_CREDENTIALS", message: "Password is incorrect" };
    }

    const result = this.#vault.deleteAccountWithSession(
      userId,
      sessionTokenHash,
      user.passwordHash,
      this.#now(),
    );
    if (result === "unauthenticated") {
      return { success: false, error: "UNAUTHENTICATED", message: "Session is no longer active" };
    }
    if (result === "conflict") {
      return { success: false, error: "INVALID_CREDENTIALS", message: "Password changed during this request" };
    }
    if (result === "last_admin") {
      return { success: false, error: "LAST_ADMIN", message: "Another administrator must remain" };
    }
    return { success: true, data: undefined };
  }

  async stopPasswordRecovery(): Promise<void> {
    this.#recoveryStopped = true;
    this.#recoveryQueue.length = 0;
    if (this.#recoveryPump) {
      clearImmediate(this.#recoveryPump);
      this.#recoveryPump = undefined;
    }
    clearTimeout(this.#recoveryExpiryTimer);
    this.#recoveryExpiryTimer = undefined;
    for (const controller of this.#recoveryControllers) {
      if (!controller.signal.aborted) controller.abort(new Error("Password recovery stopped"));
    }
    await Promise.allSettled(Array.from(this.#recoveryTasks));
  }

  #scheduleRecoveryPump(): void {
    if (this.#recoveryStopped || this.#recoveryPump) return;
    this.#recoveryPump = setImmediate(() => {
      this.#recoveryPump = undefined;
      this.#pumpRecoveryQueue();
    });
  }

  #pumpRecoveryQueue(): void {
    while (
      !this.#recoveryStopped &&
      this.#recoveryActive < RECOVERY_MAX_ACTIVE &&
      this.#recoveryOutstandingSends < RECOVERY_MAX_ACTIVE &&
      this.#recoveryQueue.length > 0
    ) {
      const item = this.#recoveryQueue.shift();
      if (!item || item.expiresAt <= this.#now()) continue;
      this.#recoveryActive++;
      let task!: Promise<void>;
      task = this.#deliverPasswordReset(item)
        .catch(() => undefined)
        .finally(() => {
          this.#recoveryActive--;
          this.#recoveryTasks.delete(task);
          this.#scheduleRecoveryPump();
        });
      this.#recoveryTasks.add(task);
    }
    this.#scheduleRecoveryExpiry();
  }
  #scheduleRecoveryExpiry(): void {
    clearTimeout(this.#recoveryExpiryTimer);
    this.#recoveryExpiryTimer = undefined;
    if (this.#recoveryStopped || this.#recoveryQueue.length === 0) return;

    let earliestExpiry = Number.POSITIVE_INFINITY;
    for (const item of this.#recoveryQueue) {
      earliestExpiry = Math.min(earliestExpiry, item.expiresAt);
    }
    const delay = Math.max(1, earliestExpiry - this.#now());
    this.#recoveryExpiryTimer = setTimeout(() => {
      this.#recoveryExpiryTimer = undefined;
      const now = this.#now();
      for (let index = this.#recoveryQueue.length - 1; index >= 0; index--) {
        const item = this.#recoveryQueue[index];
        if (item && item.expiresAt <= now) this.#recoveryQueue.splice(index, 1);
      }
      this.#scheduleRecoveryPump();
      this.#scheduleRecoveryExpiry();
    }, delay);
    this.#recoveryExpiryTimer.unref?.();
  }

  async #deliverPasswordReset(item: RecoveryQueueItem): Promise<void> {
    const mailer = this.#passwordResetMailer;
    if (!mailer || this.#recoveryStopped) return;

    const user = this.#vault.getUserByEmail(item.email);
    if (!user) return;
    const token = randomBytes(32).toString("hex");
    const tokenHash = hashSessionToken(token);
    if (!this.#vault.issuePasswordResetToken(
      user.id,
      tokenHash,
      this.#now() + PASSWORD_RESET_TTL_MS,
    )) return;

    const controller = new AbortController();
    this.#recoveryControllers.add(controller);
    this.#recoveryOutstandingSends++;
    let sendPromise: Promise<void>;
    try {
      sendPromise = Promise.resolve(mailer.send({ recipient: user.email, token }, controller.signal));
    } catch {
      this.#recoveryOutstandingSends--;
      this.#recoveryControllers.delete(controller);
      return;
    }

    const sendSettled = sendPromise.then(() => undefined, () => undefined).finally(() => {
      this.#recoveryOutstandingSends--;
      this.#recoveryControllers.delete(controller);
      this.#scheduleRecoveryPump();
    });
    let resolveAborted!: () => void;
    const aborted = new Promise<void>(resolve => {
      resolveAborted = resolve;
      controller.signal.addEventListener("abort", resolveAborted, { once: true });
    });
    const timeout = setTimeout(() => {
      controller.abort(new Error("Password reset mail timed out"));
    }, RECOVERY_MAIL_TIMEOUT_MS);
    timeout.unref?.();
    await Promise.race([sendSettled, aborted]);
    clearTimeout(timeout);
    controller.signal.removeEventListener("abort", resolveAborted);
    this.#recoveryControllers.delete(controller);
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

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.success) return invalidPasswordResult(passwordValidation.message);
    const validPassword = passwordValidation.password;


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

    const passwordHash = await hashPassword(validPassword);

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

  // ==================== Personal Access Tokens ====================

  async createPersonalAccessToken(
    userId: string,
    name: string,
    expiresInDays?: number | null,
  ): Promise<AuthResult<CreatePersonalAccessTokenResult>> {
    const trimmedName = typeof name === "string" ? name.trim() : "";
    if (!trimmedName || trimmedName.length > 100) {
      return {
        success: false,
        error: "INVALID_TOKEN",
        message: "Token name must be between 1 and 100 characters",
      };
    }

    if (expiresInDays !== null && expiresInDays !== undefined) {
      if (typeof expiresInDays !== "number" || !Number.isFinite(expiresInDays) || expiresInDays <= 0 || expiresInDays > 3650) {
        return {
          success: false,
          error: "INVALID_TOKEN",
          message: "Expiration days must be a positive number up to 3650 days",
        };
      }
    }

    try {
      const rawToken = generatePersonalAccessToken();
      const tokenHash = hashPersonalAccessToken(rawToken);
      const tokenPrefix = formatTokenPrefix(rawToken);
      const expiresAt = expiresInDays ? this.#now() + Math.round(expiresInDays * 24 * 60 * 60 * 1000) : null;

      const token = this.#vault.createPersonalAccessToken(
        userId,
        trimmedName,
        tokenHash,
        tokenPrefix,
        expiresAt,
      );

      return {
        success: true,
        data: {
          token,
          rawToken,
        },
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("Token limit reached")) {
        return {
          success: false,
          error: "TOKEN_LIMIT_REACHED",
          message: "Maximum token limit reached (25 tokens)",
        };
      }
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: message || "Failed to create personal access token",
      };
    }
  }

  async listPersonalAccessTokens(userId: string): Promise<AuthResult<PersonalAccessTokenView[]>> {
    try {
      const tokens = this.#vault.listPersonalAccessTokens(userId);
      return {
        success: true,
        data: tokens,
      };
    } catch {
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: "Failed to list personal access tokens",
      };
    }
  }

  async revokePersonalAccessToken(userId: string, tokenId: string): Promise<AuthResult<boolean>> {
    if (!tokenId || typeof tokenId !== "string") {
      return {
        success: false,
        error: "INVALID_TOKEN",
        message: "Token ID is required",
      };
    }
    try {
      const revoked = this.#vault.revokePersonalAccessToken(userId, tokenId);
      return {
        success: true,
        data: revoked,
      };
    } catch {
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: "Failed to revoke personal access token",
      };
    }
  }

  async authenticateBearerToken(
    rawToken: string,
  ): Promise<AuthResult<{ user: User; token: PersonalAccessToken }>> {
    if (!rawToken || typeof rawToken !== "string") {
      return {
        success: false,
        error: "UNAUTHENTICATED",
        message: "Invalid or missing token",
      };
    }
    const trimmed = rawToken.trim();
    if (!trimmed.startsWith("um_pat_")) {
      return {
        success: false,
        error: "UNAUTHENTICATED",
        message: "Invalid token format",
      };
    }

    try {
      const tokenHash = hashPersonalAccessToken(trimmed);
      const now = this.#now();
      const match = this.#vault.getPersonalAccessTokenByHash(tokenHash, now);
      if (!match) {
        return {
          success: false,
          error: "UNAUTHENTICATED",
          message: "Token not found or expired",
        };
      }

      // Throttled touch (update last_used_at once per minute)
      if (!match.lastUsedAt || now - match.lastUsedAt > 60_000) {
        this.#vault.touchPersonalAccessToken(match.id, now);
      }

      return {
        success: true,
        data: {
          user: match.user,
          token: {
            id: match.id,
            userId: match.userId,
            name: match.name,
            tokenHash: match.tokenHash,
            tokenPrefix: match.tokenPrefix,
            createdAt: match.createdAt,
            lastUsedAt: now,
            expiresAt: match.expiresAt,
          },
        },
      };
    } catch {
      return {
        success: false,
        error: "INTERNAL_ERROR",
        message: "Token validation failed",
      };
    }
  }
}

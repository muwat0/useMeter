import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { getCookie } from "hono/cookie";
import type { StorageVault } from "../core/storage/vault";
import type { PollerEngine } from "../core/poller/poller";
import type { ProviderRegistry } from "../core/providers/registry";
import type { AdminSystemStats, AdminUserView, InputCredential, InvitationView, UsageReport, User, UserRole } from "../types";
import { AuthService } from "../core/auth/auth";
import {
  createCorsOriginResolver,
  applySecurityHeaders,
  getSecurityHeaders,
  isOriginAllowed,
  RateLimiter,
  RATE_LIMIT_POLICIES,
  resolveClientIp,
} from "./security";
import {
  initiateCodexDeviceAuth,
  pollCodexDeviceAuth,
  exchangeCodexToken,
  initiateGoogleAuth,
  exchangeGoogleCode,
  listenForGoogleCallback,
  initiateClaudeAuth,
  exchangeClaudeCode,
  listenForClaudeCallback,
  initiateCopilotDeviceAuth,
  pollCopilotDeviceAuth,
  initiateCursorAuth,
  pollCursorAuth,
  initiateXaiDeviceAuth,
  pollXaiDeviceAuth,
  initiateKimiDeviceAuth,
  pollKimiDeviceAuth,
  initiateGeminiCliAuth,
  exchangeGeminiCliCode,
  listenForGeminiCliCallback,
  initiateOpenRouterAuth,
  exchangeOpenRouterCode,
  listenForOpenRouterCallback,
  initiateZaiAuth,
  exchangeZaiCode,
  listenForZaiCallback,
  initiateDevinAuth,
  exchangeDevinCode,
  listenForDevinCallback,
} from "../core/oauth";


interface PendingOAuthSession {
  provider: string;
  ownerId: string;
  status: "pending" | "complete" | "error";
  error?: string;
  accountLabel?: string;
}

interface AppVariables {
  user: User;
  sessionToken: string;
}
type AppEnv = { Variables: AppVariables };
type AppContext = Context<AppEnv>;

const SESSION_COOKIE = "usage_session";
const SESSION_MAX_AGE = 2_592_000;

function sessionCookie(token: string, secure: boolean): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function expiredSessionCookie(secure: boolean): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function requestIsSecure(c: AppContext): boolean {
  return process.env["NODE_ENV"] === "production" || new URL(c.req.url).protocol === "https:";
}

function originAllowed(c: AppContext, allowedOrigins?: string[] | "*"): boolean {
  const origin = c.req.header("Origin");
  if (!origin) return true;
  const reqOrigin = new URL(c.req.url).origin;
  if (origin === reqOrigin) return true;
  if (allowedOrigins) {
    return isOriginAllowed(origin, {
      allowedOrigins,
      requestOrigin: reqOrigin,
      allowCredentials: true,
    });
  }
  return false;
}

function jsonUnauthorized(c: AppContext) {
  return c.json({ success: false, error: "Unauthorized" }, 401);
}

export function createServer(
  vault: StorageVault,
  poller: PollerEngine,
  _registry?: ProviderRegistry,
  authService?: AuthService,
  options?: { rateLimiter?: RateLimiter }
): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const auth = authService ?? new AuthService(vault);
  const pendingOAuth = new Map<string, PendingOAuthSession>();
  const pendingDeviceOwners = new Map<string, string>();
  const rateLimiter = options?.rateLimiter ?? new RateLimiter();

  function getClientIp(c: AppContext): string {
    return resolveClientIp(c.req.raw, {
      trustProxy: process.env["TRUST_PROXY"] === "true" || process.env["TRUST_PROXY"] === "1",
    });
  }

  function rateLimitResponse(c: AppContext, retryAfterSec = 60, message = "Too many requests. Please try again later.") {
    c.header("Retry-After", String(retryAfterSec));
    return c.json(
      {
        success: false,
        error: message,
        retryAfter: retryAfterSec,
      },
      429
    );
  }

  const allowedOriginsEnv = process.env["CORS_ALLOWED_ORIGINS"] || process.env["USEMETER_ALLOWED_ORIGINS"];
  const allowedOriginsList = allowedOriginsEnv
    ? allowedOriginsEnv === "*"
      ? "*"
      : allowedOriginsEnv.split(",").map(o => o.trim()).filter(Boolean)
    : undefined;

  const corsOriginResolver = createCorsOriginResolver({
    allowedOrigins: allowedOriginsList,
    allowCredentials: true,
  });

  // Global response security headers (HSTS only in production/HTTPS)
  app.use("*", async (c, next) => {
    const secure = requestIsSecure(c);
    const secHeaders = getSecurityHeaders(secure);
    for (const [k, v] of Object.entries(secHeaders)) {
      c.header(k, v);
    }
    try {
      await next();
    } finally {
      if (c.res) {
        applySecurityHeaders(c.res.headers, secure);
      }
    }
  });

  // Strict CORS resolver (no credentialed wildcard, same-origin default)
  app.use(
    "*",
    cors({
      origin: (incoming, c) => corsOriginResolver(incoming, c),
      credentials: true,
    })
  );

  app.use("*", async (c, next) => {
    if (c.req.method === "OPTIONS") return next();
    const path = new URL(c.req.url).pathname;
    const publicRoute =
      path === "/health" ||
      (path === "/login" && c.req.method === "GET") ||
      (path === "/register" && c.req.method === "GET") ||
      ((path === "/invite" || path.startsWith("/invite/")) && c.req.method === "GET") ||
      (path.startsWith("/api/invitations/") && c.req.method === "POST" && path.endsWith("/accept")) ||
      path === "/api/auth/login" ||
      path === "/api/auth/register" ||
      path === "/api/auth/logout";
    const token = getCookie(c, SESSION_COOKIE);
    if (token) {
      const result = await auth.authenticate(token);
      if (result.success) {
        c.set("user", result.data);
        c.set("sessionToken", token);
      }
    }
    const user = c.get("user");
    if (c.req.method !== "GET" && c.req.method !== "HEAD" && !publicRoute && !originAllowed(c, allowedOriginsList)) {
      return c.json({ success: false, error: "Cross-origin request rejected" }, 403);
    }
    if (publicRoute) {
      if (user && (path === "/login" || path === "/register")) return c.redirect("/");
      return next();
    }
    if (!user) {
      if (path.startsWith("/api/")) return jsonUnauthorized(c);
      return c.redirect("/login");
    }
    if (path === "/admin" || path.startsWith("/admin/")) {
      if (user.role !== "admin") {
        return c.html(renderAdminForbiddenHtml(), 403);
      }
    }
    if (path === "/api/admin" || path.startsWith("/api/admin/")) {
      if (user.role !== "admin") {
        return c.json({ success: false, error: "Admin access required" }, 403);
      }
    }
    return next();
  });

  // Public health endpoint.
  app.get("/health", c => {
    return c.json({
      status: "ok",
      integrity: vault.checkIntegrity(),
      pollerRunning: poller.isRunning(),
    });
  });

  // Auth UI routes
  app.get("/login", c => c.html(renderAuthPageHtml({ mode: "login" })));
  app.get("/register", c => {
    const registrationDisabled = vault.getUserCount() > 0 && !vault.isRegistrationAllowed();
    return c.html(renderAuthPageHtml({ mode: "register", registrationDisabled }));
  });

  // Auth API routes
  app.post("/api/auth/register", async c => {
    try {
      const ip = getClientIp(c);
      const rl = rateLimiter.check(`registration:${ip}`, RATE_LIMIT_POLICIES.registration);
      if (!rl.allowed) {
        return rateLimitResponse(c, rl.retryAfterSec, "Too many registration attempts. Please try again later.");
      }
      if (vault.getUserCount() > 0 && !vault.isRegistrationAllowed()) {
        return c.json({ success: false, error: "Registration is disabled by administrator" }, 403);
      }
      const body = (await c.req.json().catch(() => ({}))) as { email?: string; password?: string };
      if (!body.email || !body.password) {
        return c.json({ success: false, error: "Email and password are required" }, 400);
      }
      const result = await auth.register(body.email, body.password);
      if (!result.success) {
        return c.json({ success: false, error: result.message }, 400);
      }
      c.header("Set-Cookie", sessionCookie(result.data.token, requestIsSecure(c)));
      return c.json(
        {
          success: true,
          user: {
            id: result.data.user.id,
            email: result.data.user.email,
          },
        },
        201
      );
    } catch {
      return c.json({ success: false, error: "Internal server error" }, 500);
    }
  });

  app.post("/api/auth/login", async c => {
    try {
      const ip = getClientIp(c);
      const rl = rateLimiter.check(`auth:${ip}`, RATE_LIMIT_POLICIES.auth);
      if (!rl.allowed) {
        return rateLimitResponse(c, rl.retryAfterSec, "Too many login attempts. Please try again later.");
      }
      const body = (await c.req.json().catch(() => ({}))) as { email?: string; password?: string };
      if (!body.email || !body.password) {
        return c.json({ success: false, error: "Invalid email or password" }, 401);
      }
      const result = await auth.login(body.email, body.password);
      if (!result.success) {
        return c.json({ success: false, error: "Invalid email or password" }, 401);
      }
      c.header("Set-Cookie", sessionCookie(result.data.token, requestIsSecure(c)));
      return c.json({
        success: true,
        user: {
          id: result.data.user.id,
          email: result.data.user.email,
        },
      });
    } catch {
      return c.json({ success: false, error: "Internal server error" }, 500);
    }
  });

  // Public Invitation routes
  app.get("/invite/:token", c => {
    const token = c.req.param("token");
    return c.html(renderInvitePageHtml({ token }));
  });

  app.get("/invite", c => {
    const token = c.req.query("token") || "";
    return c.html(renderInvitePageHtml({ token }));
  });

  app.post("/api/invitations/:token/accept", async c => {
    try {
      const token = c.req.param("token");
      if (!token || typeof token !== "string" || !token.trim()) {
        return c.json({ success: false, error: "Invalid or expired invitation" }, 400);
      }
      const body = (await c.req.json().catch(() => ({}))) as { password?: string };
      if (!body.password || typeof body.password !== "string") {
        return c.json({ success: false, error: "Password is required" }, 400);
      }
      const trimmedPassword = body.password;
      if (trimmedPassword.length < 12 || trimmedPassword.length > 256) {
        return c.json({ success: false, error: "Password must be between 12 and 256 characters" }, 400);
      }

      const result = await auth.acceptInvitation(token.trim(), trimmedPassword);
      if (!result.success) {
        return c.json({ success: false, error: "Invalid or expired invitation" }, 400);
      }

      c.header("Set-Cookie", sessionCookie(result.data.token, requestIsSecure(c)));
      return c.json(
        {
          success: true,
          user: {
            id: result.data.user.id,
            email: result.data.user.email,
          },
        },
        200
      );
    } catch {
      return c.json({ success: false, error: "Invalid or expired invitation" }, 400);
    }
  });

  app.post("/api/auth/logout", async c => {
    const token = getCookie(c, SESSION_COOKIE) || c.get("sessionToken");
    if (token) {
      await auth.logout(token);
    }
    c.header("Set-Cookie", expiredSessionCookie(requestIsSecure(c)));
    return c.json({ success: true, ok: true });
  });

  app.get("/api/auth/me", c => {
    const user = c.get("user");
    return c.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  });

  // Admin UI route
  app.get("/admin", async c => {
    const user = c.get("user");
    const stats = vault.getSystemStatsAdmin(poller.isRunning());
    const users = vault.listUsersAdmin();
    const invitationsRes = await auth.listInvitations(user.id);
    const invitations = invitationsRes.success ? invitationsRes.data : [];
    return c.html(renderAdminDashboardHtml({ user, stats, users, invitations }));
  });

  // Admin API routes: Invitations
  app.get("/api/admin/invitations", async c => {
    const user = c.get("user");
    const result = await auth.listInvitations(user.id);
    if (!result.success) {
      return c.json({ success: false, error: result.message }, 500);
    }
    return c.json({
      success: true,
      data: result.data,
      invitations: result.data,
    });
  });

  app.post("/api/admin/invitations", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json().catch(() => ({}))) as { email?: string };
      if (!body.email || typeof body.email !== "string" || !body.email.trim()) {
        return c.json({ success: false, error: "Email address is required" }, 400);
      }
      const result = await auth.createInvitation(user.id, body.email.trim());
      if (!result.success) {
        return c.json({ success: false, error: result.message }, 400);
      }
      const reqOrigin = new URL(c.req.url).origin;
      const inviteUrl = `${reqOrigin}/invite/${result.data.token}`;
      return c.json(
        {
          success: true,
          inviteUrl,
          token: result.data.token,
          invitation: result.data.invitation,
          data: {
            inviteUrl,
            invitation: result.data.invitation,
          },
        },
        201
      );
    } catch {
      return c.json({ success: false, error: "Internal server error" }, 500);
    }
  });

  app.delete("/api/admin/invitations/:id", async c => {
    try {
      const user = c.get("user");
      const id = c.req.param("id");
      if (!id) {
        return c.json({ success: false, error: "Invitation ID is required" }, 400);
      }
      const result = await auth.revokeInvitation(user.id, id);
      if (!result.success) {
        return c.json({ success: false, error: result.message }, 400);
      }
      return c.json({ success: true, revoked: true });
    } catch {
      return c.json({ success: false, error: "Failed to revoke invitation" }, 500);
    }
  });

  // Admin API routes
  app.get("/api/admin/stats", c => {
    const stats = vault.getSystemStatsAdmin(poller.isRunning());
    return c.json({ success: true, data: stats, ...stats });
  });
  app.get("/api/admin/settings", c => {
    const allowRegistration = vault.isRegistrationAllowed();
    return c.json({
      success: true,
      allowRegistration,
      data: { allowRegistration },
    });
  });

  app.patch("/api/admin/settings/registration", async c => {
    try {
      const body = (await c.req.json()) as { allowRegistration?: boolean };
      if (typeof body.allowRegistration !== "boolean") {
        return c.json({ success: false, error: "Invalid allowRegistration: must be boolean" }, 400);
      }
      vault.setRegistrationAllowed(body.allowRegistration);
      const allowRegistration = vault.isRegistrationAllowed();
      return c.json({
        success: true,
        allowRegistration,
        data: { allowRegistration },
      });
    } catch {
      return c.json({ success: false, error: "Invalid request payload" }, 400);
    }
  });


  app.get("/api/admin/users", c => {
    const users = vault.listUsersAdmin();
    return c.json({ success: true, data: users, users });
  });

  app.patch("/api/admin/users/:id/role", async c => {
    try {
      const user = c.get("user");
      const targetId = c.req.param("id");
      const body = (await c.req.json()) as { role?: UserRole };
      if (!body.role || (body.role !== "admin" && body.role !== "user")) {
        return c.json({ success: false, error: "Invalid role: must be 'admin' or 'user'" }, 400);
      }
      const result = vault.updateUserRoleAdmin(user.id, targetId, body.role);
      if (!result.success) {
        return c.json({ success: false, error: result.error || "Failed to update role" }, 400);
      }
      return c.json({ success: true });
    } catch {
      return c.json({ success: false, error: "Invalid request payload" }, 400);
    }
  });

  app.delete("/api/admin/users/:id", async c => {
    try {
      const user = c.get("user");
      const targetId = c.req.param("id");
      const result = vault.deleteUserAdmin(user.id, targetId);
      if (!result.success) {
        return c.json({ success: false, error: result.error || "Failed to delete user" }, 400);
      }
      return c.json({ success: true });
    } catch {
      return c.json({ success: false, error: "Failed to delete user" }, 500);
    }
  });

  const handleUsage = (c: AppContext) => {
    const user = c.get("user");
    const latest = vault.getLatestUsage(user.id);
    const credentials = new Map(vault.listCredentials(user.id).map(credential => [credential.id, credential]));
    const data = latest.map(report => {
      const credential = report.credentialId ? credentials.get(report.credentialId) : undefined;
      return {
        ...report,
        accountLabel: credential?.accountLabel || report.accountLabel,
        createdAt: credential?.createdAt,
        accent: credential?.accent || "default",
        metadata: credential?.metadata,
      };
    });
    return c.json({ success: true, data });
  };
  app.get("/api/usage", handleUsage);
  app.get("/api/data", handleUsage);

  // API: Trigger poll now for authenticated user's credentials
  app.post("/api/poll", async c => {
    try {
      const user = c.get("user");
      const rl = rateLimiter.check(`manualPoll:${user.id}:all`, RATE_LIMIT_POLICIES.manualPoll);
      if (!rl.allowed) {
        return rateLimitResponse(c, rl.retryAfterSec, "Rate limit exceeded. Please wait before polling again.");
      }
      const credentials = vault.listCredentials(user.id);
      const reports: UsageReport[] = [];
      for (const cred of credentials) {
        const report = await poller.pollCredential(user.id, cred.id);
        if (report) reports.push(report);
      }
      return c.json({ success: true, count: reports.length, data: reports });
    } catch {
      return c.json({ success: false, error: "Failed to poll credentials" }, 500);
    }
  });

  // API: Trigger poll for a specific credential
  app.post("/api/credentials/:id/poll", async c => {
    try {
      const user = c.get("user");
      const id = c.req.param("id");
      const rl = rateLimiter.check(`manualPoll:${user.id}:${id}`, RATE_LIMIT_POLICIES.manualPoll);
      if (!rl.allowed) {
        return rateLimitResponse(c, rl.retryAfterSec, "Rate limit exceeded. Please wait before polling again.");
      }
      const cred = vault.getCredential(user.id, id);
      if (!cred) {
        return c.json({ success: false, error: "Credential not found" }, 404);
      }
      const report = await poller.pollCredential(user.id, id);
      return c.json({ success: true, data: report });
    } catch {
      return c.json({ success: false, error: "Failed to poll credential" }, 500);
    }
  });

  // API: List credentials (masked) for authenticated user
  app.get("/api/credentials", c => {
    const user = c.get("user");
    const creds = vault.listCredentials(user.id);
    const masked = creds.map(cr => {
      const s = cr.secret;
      const maskedSecret = s.length > 8 ? `${s.slice(0, 4)}...${s.slice(-4)}` : "********";
      return {
        id: cr.id,
        provider: cr.provider,
        accountLabel: cr.accountLabel,
        maskedSecret,
        createdAt: cr.createdAt,
        accent: cr.accent || "default",
      };
    });
    return c.json({ success: true, data: masked });
  });

  // API: Add manual credential for authenticated user
  app.post("/api/credentials", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json()) as InputCredential & { accent?: string | null; ownerId?: string };
      if (!body.provider || !body.accountLabel || !body.secret) {
        return c.json({ success: false, error: "Tüm alanlar zorunludur." }, 400);
      }

      if (body.accent) {
        body.metadata = { ...(body.metadata || {}), accent: body.accent };
      }

      const { ownerId: _, ...inputData } = body;
      const saved = vault.saveCredential(user.id, {
        ...inputData,
        ownerId: user.id,
      });
      const initialReport = await poller.pollCredential(user.id, saved.id);
      if (initialReport?.error) {
        vault.deleteCredential(user.id, saved.id);
        return c.json({ success: false, error: initialReport.error }, 400);
      }
      return c.json({
        success: true,
        data: {
          id: saved.id,
          provider: saved.provider,
          accountLabel: saved.accountLabel,
          accent: body.accent || null,
        },
      });
    } catch {
      return c.json({ success: false, error: "Failed to save credential" }, 500);
    }
  });

  // API: Update credential (label and/or accent)
  app.patch("/api/credentials/:id", async c => {
    try {
      const user = c.get("user");
      const id = c.req.param("id");
      const body = (await c.req.json()) as { accountLabel?: string; accent?: string | null };

      const updated = vault.updateCredential(user.id, id, body);

      if (!updated) {
        return c.json({ success: false, error: "Credential not found" }, 404);
      }
      return c.json({ success: true, updated: true });
    } catch {
      return c.json({ success: false, error: "Failed to update credential" }, 500);
    }
  });

  // API: Delete credential
  app.delete("/api/credentials/:id", c => {
    const user = c.get("user");
    const id = c.req.param("id");
    const ok = vault.deleteCredential(user.id, id);
    if (!ok) {
      return c.json({ success: false, error: "Credential not found" }, 404);
    }
    return c.json({ success: true });
  });

  // OAuth: Codex Device Auth - Initiate
  app.post("/api/oauth/codex/initiate", async c => {
    try {
      const user = c.get("user");
      const result = await initiateCodexDeviceAuth();
      pendingDeviceOwners.set(result.deviceAuthId, user.id);
      return c.json({ success: true, data: result });
    } catch {
      return c.json({ success: false, error: "Failed to initiate device authorization" }, 500);
    }
  });

  // OAuth: Codex Device Auth - Poll & Exchange
  app.post("/api/oauth/codex/poll", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json().catch(() => ({}))) as { deviceAuthId: string; userCode: string; label?: string };
      const flowKey = body.deviceAuthId || getClientIp(c);
      const rl = rateLimiter.check(`oauthDevicePoll:${user.id}:codex:${flowKey}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
      if (!rl.allowed) {
        c.header("Retry-After", String(rl.retryAfterSec || 60));
        return c.json({ status: "error", error: "Too many polling attempts. Please slow down.", retryAfter: rl.retryAfterSec }, 429);
      }
      const boundOwner = pendingDeviceOwners.get(body.deviceAuthId);
      if (boundOwner && boundOwner !== user.id) {
        return c.json({ status: "error", error: "Device authentication owned by another user" }, 403);
      }
      const pollRes = await pollCodexDeviceAuth(body.deviceAuthId, body.userCode);

      if (pollRes.status === "pending") {
        return c.json({ status: "pending" });
      }

      if (pollRes.status === "error") {
        return c.json({ status: "error", error: pollRes.message });
      }

      pendingDeviceOwners.delete(body.deviceAuthId);
      const tokenResult = await exchangeCodexToken(pollRes.authorizationCode, pollRes.codeVerifier);
      const accountLabel = tokenResult.email || body.label || "ChatGPT Codex";

      const saved = vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "openai-codex",
        accountLabel,
        credentialType: "oauth",
        secret: tokenResult.accessToken,
        metadata: {
          refreshToken: tokenResult.refreshToken,
          accountId: tokenResult.accountId,
          email: tokenResult.email,
          planType: tokenResult.planType,
        },
      });

      const initialReport = await poller.pollCredential(user.id, saved.id);
      if (initialReport?.error) {
        vault.deleteCredential(user.id, saved.id);
        return c.json({ status: "error", error: initialReport.error });
      }

      return c.json({
        status: "complete",
        data: { id: saved.id, accountLabel: saved.accountLabel },
      });
    } catch {
      return c.json({ status: "error", error: "Failed to complete device authorization" }, 500);
    }
  });

  // OAuth: Google (Antigravity / Gemini) - Initiate
  app.post("/api/oauth/google/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, verifier, state } = initiateGoogleAuth();
      const sessionId = state;

      pendingOAuth.set(sessionId, { provider: "antigravity", ownerId: user.id, status: "pending" });

      listenForGoogleCallback(state)
        .then(async code => {
          const tokens = await exchangeGoogleCode(code, verifier);
          const label = tokens.email || "Antigravity";

          const saved = vault.saveCredential(user.id, {
            ownerId: user.id,
            provider: "antigravity",
            accountLabel: label,
            credentialType: "oauth",
            secret: tokens.accessToken,
            metadata: {
              refreshToken: tokens.refreshToken,
              email: tokens.email,
            },
          });

          const initialReport = await poller.pollCredential(user.id, saved.id);
          if (initialReport?.error) {
            vault.deleteCredential(user.id, saved.id);
            pendingOAuth.set(sessionId, { provider: "antigravity", ownerId: user.id, status: "error", error: initialReport.error });
            return;
          }
          pendingOAuth.set(sessionId, { provider: "antigravity", ownerId: user.id, status: "complete", accountLabel: label });
        })
        .catch(() => {
          pendingOAuth.set(sessionId, { provider: "antigravity", ownerId: user.id, status: "error", error: "Authorization failed" });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch {
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: Claude - Initiate
  app.post("/api/oauth/claude/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, verifier, state } = initiateClaudeAuth();
      const sessionId = state;

      pendingOAuth.set(sessionId, { provider: "anthropic", ownerId: user.id, status: "pending" });

      listenForClaudeCallback(state)
        .then(async code => {
          const tokens = await exchangeClaudeCode(code, verifier);
          let label = "Claude Pro/Max";
          try {
            if (tokens.accessToken) {
              const profileRes = await fetch("https://api.anthropic.com/api/oauth/user_profile", {
                headers: { Authorization: `Bearer ${tokens.accessToken}`, Accept: "application/json", "User-Agent": "claude-cli/0.2.148 (external, cli)" },
              });
              if (profileRes.ok) {
                const profile = (await profileRes.json()) as { email?: string; user?: { email?: string; id?: string }; id?: string };
                const discoveredEmail = profile.email || profile.user?.email;
                const discoveredId = profile.user?.id || profile.id;
                if (discoveredEmail && discoveredEmail.trim()) label = discoveredEmail.trim();
                else if (discoveredId && String(discoveredId).trim()) label = String(discoveredId).trim();
              }
            }
          } catch {}

          const saved = vault.saveCredential(user.id, {
            ownerId: user.id,
            provider: "anthropic",
            accountLabel: label,
            credentialType: "oauth",
            secret: tokens.accessToken,
            metadata: {
              refreshToken: tokens.refreshToken,
              email: label !== "Claude Pro/Max" ? label : undefined,
            },
          });
          const initialReport = await poller.pollCredential(user.id, saved.id);
          if (initialReport?.error) {
            vault.deleteCredential(user.id, saved.id);
            pendingOAuth.set(sessionId, { provider: "anthropic", ownerId: user.id, status: "error", error: initialReport.error });
            return;
          }
          pendingOAuth.set(sessionId, { provider: "anthropic", ownerId: user.id, status: "complete", accountLabel: label });
        })
        .catch(() => {
          pendingOAuth.set(sessionId, { provider: "anthropic", ownerId: user.id, status: "error", error: "Authorization failed" });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch {
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: GitHub Copilot - Initiate & Poll
  app.post("/api/oauth/copilot/initiate", async c => {
    try {
      const user = c.get("user");
      const result = await initiateCopilotDeviceAuth();
      pendingDeviceOwners.set(result.deviceCode, user.id);
      return c.json({ success: true, data: result });
    } catch {
      return c.json({ success: false, error: "Failed to initiate device authorization" }, 500);
    }
  });

  app.post("/api/oauth/copilot/poll", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json().catch(() => ({}))) as { deviceCode: string; label?: string };
      const flowKey = body.deviceCode || getClientIp(c);
      const rl = rateLimiter.check(`oauthDevicePoll:${user.id}:copilot:${flowKey}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
      if (!rl.allowed) {
        c.header("Retry-After", String(rl.retryAfterSec || 60));
        return c.json({ status: "error", error: "Too many polling attempts. Please slow down.", retryAfter: rl.retryAfterSec }, 429);
      }
      const boundOwner = pendingDeviceOwners.get(body.deviceCode);
      if (boundOwner && boundOwner !== user.id) {
        return c.json({ status: "error", error: "Device authentication owned by another user" }, 403);
      }
      const pollRes = await pollCopilotDeviceAuth(body.deviceCode);
      if (pollRes.status === "pending" || pollRes.status === "slow_down") {
        return c.json({ status: pollRes.status });
      }
      if (pollRes.status === "error") {
        return c.json({ status: "error", error: pollRes.message });
      }
      pendingDeviceOwners.delete(body.deviceCode);
      const label = (body.label && body.label !== "GitHub Copilot" ? body.label : (pollRes.token.login || pollRes.token.email)) || pollRes.token.login || pollRes.token.email || "GitHub Copilot";
      const saved = vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "github-copilot",
        accountLabel: label,
        credentialType: "oauth",
        secret: pollRes.token.accessToken,
        metadata: {
          login: pollRes.token.login,
          email: pollRes.token.email,
        },
      });
      const initialReport = await poller.pollCredential(user.id, saved.id);
      if (initialReport?.error) {
        vault.deleteCredential(user.id, saved.id);
        return c.json({ status: "error", error: initialReport.error });
      }
      return c.json({ status: "complete", data: { id: saved.id, accountLabel: saved.accountLabel } });
    } catch {
      return c.json({ status: "error", error: "Failed to complete device authorization" }, 500);
    }
  });

  // OAuth: Cursor - Initiate & Poll
  app.post("/api/oauth/cursor/initiate", async c => {
    try {
      const user = c.get("user");
      const result = await initiateCursorAuth();
      pendingDeviceOwners.set(result.uuid, user.id);
      return c.json({ success: true, data: result });
    } catch {
      return c.json({ success: false, error: "Failed to initiate cursor authorization" }, 500);
    }
  });

  app.post("/api/oauth/cursor/poll", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json().catch(() => ({}))) as { uuid: string; verifier: string; label?: string };
      const flowKey = body.uuid || getClientIp(c);
      const rl = rateLimiter.check(`oauthDevicePoll:${user.id}:cursor:${flowKey}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
      if (!rl.allowed) {
        c.header("Retry-After", String(rl.retryAfterSec || 60));
        return c.json({ status: "error", error: "Too many polling attempts. Please slow down.", retryAfter: rl.retryAfterSec }, 429);
      }
      const boundOwner = pendingDeviceOwners.get(body.uuid);
      if (boundOwner && boundOwner !== user.id) {
        return c.json({ status: "error", error: "Device authentication owned by another user" }, 403);
      }
      const pollRes = await pollCursorAuth(body.uuid, body.verifier);
      if (pollRes.status === "pending") {
        return c.json({ status: "pending" });
      }
      if (pollRes.status === "error") {
        return c.json({ status: "error", error: pollRes.message });
      }
      pendingDeviceOwners.delete(body.uuid);
      const label = (body.label && body.label !== "Cursor" ? body.label : pollRes.email) || pollRes.email || "Cursor";
      const saved = vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "cursor",
        accountLabel: label,
        credentialType: "oauth",
        secret: pollRes.accessToken,
        metadata: {
          refreshToken: pollRes.refreshToken,
          email: pollRes.email,
        },
      });
      const initialReport = await poller.pollCredential(user.id, saved.id);
      if (initialReport?.error) {
        vault.deleteCredential(user.id, saved.id);
        return c.json({ status: "error", error: initialReport.error });
      }
      return c.json({ status: "complete", data: { id: saved.id, accountLabel: saved.accountLabel } });
    } catch {
      return c.json({ status: "error", error: "Failed to complete cursor authorization" }, 500);
    }
  });

  // OAuth: xAI Grok - Initiate & Poll
  app.post("/api/oauth/xai/initiate", async c => {
    try {
      const user = c.get("user");
      const result = await initiateXaiDeviceAuth();
      pendingDeviceOwners.set(result.deviceCode, user.id);
      return c.json({ success: true, data: result });
    } catch {
      return c.json({ success: false, error: "Failed to initiate device authorization" }, 500);
    }
  });

  app.post("/api/oauth/xai/poll", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json().catch(() => ({}))) as { deviceCode: string; label?: string };
      const flowKey = body.deviceCode || getClientIp(c);
      const rl = rateLimiter.check(`oauthDevicePoll:${user.id}:xai:${flowKey}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
      if (!rl.allowed) {
        c.header("Retry-After", String(rl.retryAfterSec || 60));
        return c.json({ status: "error", error: "Too many polling attempts. Please slow down.", retryAfter: rl.retryAfterSec }, 429);
      }
      const boundOwner = pendingDeviceOwners.get(body.deviceCode);
      if (boundOwner && boundOwner !== user.id) {
        return c.json({ status: "error", error: "Device authentication owned by another user" }, 403);
      }
      const pollRes = await pollXaiDeviceAuth(body.deviceCode);
      if (pollRes.status === "pending" || pollRes.status === "slow_down") {
        return c.json({ status: pollRes.status });
      }
      if (pollRes.status === "error") {
        return c.json({ status: "error", error: pollRes.message });
      }
      pendingDeviceOwners.delete(body.deviceCode);
      const label = (body.label && body.label !== "xAI Grok" ? body.label : pollRes.email) || pollRes.email || "xAI Grok";
      const saved = vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "xai-oauth",
        accountLabel: label,
        credentialType: "oauth",
        secret: pollRes.accessToken,
        metadata: {
          refreshToken: pollRes.refreshToken,
          email: pollRes.email,
        },
      });
      const initialReport = await poller.pollCredential(user.id, saved.id);
      if (initialReport?.error) {
        vault.deleteCredential(user.id, saved.id);
        return c.json({ status: "error", error: initialReport.error });
      }
      return c.json({ status: "complete", data: { id: saved.id, accountLabel: saved.accountLabel } });
    } catch {
      return c.json({ status: "error", error: "Failed to complete device authorization" }, 500);
    }
  });

  // OAuth: Kimi Code - Initiate & Poll
  app.post("/api/oauth/kimi/initiate", async c => {
    try {
      const user = c.get("user");
      const result = await initiateKimiDeviceAuth();
      pendingDeviceOwners.set(result.deviceCode, user.id);
      return c.json({ success: true, data: result });
    } catch {
      return c.json({ success: false, error: "Failed to initiate device authorization" }, 500);
    }
  });

  app.post("/api/oauth/kimi/poll", async c => {
    try {
      const user = c.get("user");
      const body = (await c.req.json().catch(() => ({}))) as { deviceCode: string; deviceId: string; label?: string };
      const flowKey = body.deviceCode || getClientIp(c);
      const rl = rateLimiter.check(`oauthDevicePoll:${user.id}:kimi:${flowKey}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
      if (!rl.allowed) {
        c.header("Retry-After", String(rl.retryAfterSec || 60));
        return c.json({ status: "error", error: "Too many polling attempts. Please slow down.", retryAfter: rl.retryAfterSec }, 429);
      }
      const boundOwner = pendingDeviceOwners.get(body.deviceCode);
      if (boundOwner && boundOwner !== user.id) {
        return c.json({ status: "error", error: "Device authentication owned by another user" }, 403);
      }
      const pollRes = await pollKimiDeviceAuth(body.deviceCode, body.deviceId);
      if (pollRes.status === "pending" || pollRes.status === "slow_down") {
        return c.json({ status: pollRes.status });
      }
      if (pollRes.status === "error") {
        return c.json({ status: "error", error: pollRes.message });
      }
      pendingDeviceOwners.delete(body.deviceCode);
      const label = (body.label && body.label !== "Kimi Code" ? body.label : (pollRes.accountId || "Kimi Code")) || pollRes.accountId || "Kimi Code";
      const saved = vault.saveCredential(user.id, {
        ownerId: user.id,
        provider: "kimi-code",
        accountLabel: label,
        credentialType: "oauth",
        secret: pollRes.accessToken,
        metadata: {
          refreshToken: pollRes.refreshToken,
          accountId: pollRes.accountId,
        },
      });
      const initialReport = await poller.pollCredential(user.id, saved.id);
      if (initialReport?.error) {
        vault.deleteCredential(user.id, saved.id);
        return c.json({ status: "error", error: initialReport.error });
      }
      return c.json({ status: "complete", data: { id: saved.id, accountLabel: saved.accountLabel } });
    } catch {
      return c.json({ status: "error", error: "Failed to complete device authorization" }, 500);
    }
  });

  // OAuth: Google Gemini CLI - Initiate
  app.post("/api/oauth/gemini-cli/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, state } = initiateGeminiCliAuth();
      const sessionId = state;
      pendingOAuth.set(sessionId, { provider: "google-gemini-cli", ownerId: user.id, status: "pending" });

      listenForGeminiCliCallback(state)
        .then(async code => {
          const tokens = await exchangeGeminiCliCode(code);
          const label = tokens.email || tokens.projectId || "Gemini CLI";
          const saved = vault.saveCredential(user.id, {
            ownerId: user.id,
            provider: "google-gemini-cli",
            accountLabel: label,
            credentialType: "oauth",
            secret: tokens.accessToken,
            metadata: {
              refreshToken: tokens.refreshToken,
              email: tokens.email,
              projectId: tokens.projectId,
            },
          });
          const initialReport = await poller.pollCredential(user.id, saved.id);
          if (initialReport?.error) {
            vault.deleteCredential(user.id, saved.id);
            pendingOAuth.set(sessionId, { provider: "google-gemini-cli", ownerId: user.id, status: "error", error: initialReport.error });
            return;
          }
          pendingOAuth.set(sessionId, { provider: "google-gemini-cli", ownerId: user.id, status: "complete", accountLabel: label });
        })
        .catch(() => {
          pendingOAuth.set(sessionId, { provider: "google-gemini-cli", ownerId: user.id, status: "error", error: "Authorization failed" });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch {
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: OpenRouter - Initiate
  app.post("/api/oauth/openrouter/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, verifier, sessionId } = initiateOpenRouterAuth();
      pendingOAuth.set(sessionId, { provider: "openrouter", ownerId: user.id, status: "pending" });

      listenForOpenRouterCallback()
        .then(async code => {
          const keyResult = await exchangeOpenRouterCode(code, verifier);
          const label = keyResult.label || "OpenRouter";
          const saved = vault.saveCredential(user.id, {
            ownerId: user.id,
            provider: "openrouter",
            accountLabel: label,
            credentialType: "api_key",
            secret: keyResult.apiKey,
            metadata: {
              source: "oauth-pkce",
            },
          });
          const initialReport = await poller.pollCredential(user.id, saved.id);
          if (initialReport?.error) {
            vault.deleteCredential(user.id, saved.id);
            pendingOAuth.set(sessionId, { provider: "openrouter", ownerId: user.id, status: "error", error: initialReport.error });
            return;
          }
          pendingOAuth.set(sessionId, { provider: "openrouter", ownerId: user.id, status: "complete", accountLabel: label });
        })
        .catch(() => {
          pendingOAuth.set(sessionId, { provider: "openrouter", ownerId: user.id, status: "error", error: "Authorization failed" });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch {
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: Zhipu AI (GLM) - Initiate
  app.post("/api/oauth/zai/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, state, sessionId } = initiateZaiAuth();
      pendingOAuth.set(sessionId, { provider: "zai", ownerId: user.id, status: "pending" });

      listenForZaiCallback(state)
        .then(async code => {
          const keyResult = await exchangeZaiCode(code, state);
          const label = keyResult.email || "Zhipu AI";
          const saved = vault.saveCredential(user.id, {
            ownerId: user.id,
            provider: "zai",
            accountLabel: label,
            credentialType: "api_key",
            secret: keyResult.apiKey,
            metadata: {
              email: keyResult.email,
              accountId: keyResult.accountId,
              source: "oauth",
            },
          });
          const initialReport = await poller.pollCredential(user.id, saved.id);
          if (initialReport?.error) {
            vault.deleteCredential(user.id, saved.id);
            pendingOAuth.set(sessionId, { provider: "zai", ownerId: user.id, status: "error", error: initialReport.error });
            return;
          }
          pendingOAuth.set(sessionId, { provider: "zai", ownerId: user.id, status: "complete", accountLabel: label });
        })
        .catch(() => {
          pendingOAuth.set(sessionId, { provider: "zai", ownerId: user.id, status: "error", error: "Authorization failed" });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch {
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: Devin - Initiate
  app.post("/api/oauth/devin/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, verifier, state, sessionId } = initiateDevinAuth();
      pendingOAuth.set(sessionId, { provider: "devin", ownerId: user.id, status: "pending" });

      listenForDevinCallback(state)
        .then(async code => {
          const tokenResult = await exchangeDevinCode(code, verifier);
          const initialLabel = tokenResult.email || "Devin";
          const saved = vault.saveCredential(user.id, {
            ownerId: user.id,
            provider: "devin",
            accountLabel: initialLabel,
            credentialType: "api_key",
            secret: tokenResult.token,
            metadata: {
              email: tokenResult.email,
              source: "oauth-pkce",
            },
          });
          const initialReport = await poller.pollCredential(user.id, saved.id);
          if (initialReport?.error) {
            vault.deleteCredential(user.id, saved.id);
            pendingOAuth.set(sessionId, { provider: "devin", ownerId: user.id, status: "error", error: initialReport.error });
            return;
          }
          const resolvedLabel = initialReport && initialReport.accountLabel && initialReport.accountLabel !== "Devin" && initialReport.accountLabel !== "Default"
            ? initialReport.accountLabel
            : saved.accountLabel;
          if (resolvedLabel !== saved.accountLabel) {
            vault.updateCredentialLabel(user.id, saved.id, resolvedLabel);
          }
          pendingOAuth.set(sessionId, { provider: "devin", ownerId: user.id, status: "complete", accountLabel: resolvedLabel });
        })
        .catch(() => {
          pendingOAuth.set(sessionId, { provider: "devin", ownerId: user.id, status: "error", error: "Authorization failed" });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch {
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: Check pending session status (Google & Claude)
  app.get("/api/oauth/status/:sessionId", c => {
    const user = c.get("user");
    const sessionId = c.req.param("sessionId");
    const rl = rateLimiter.check(`oauthDevicePoll:${user ? user.id : getClientIp(c)}:status:${sessionId}`, RATE_LIMIT_POLICIES.oauthDevicePoll);
    if (!rl.allowed) {
      c.header("Retry-After", String(rl.retryAfterSec || 60));
      return c.json({ status: "error", error: "Too many requests", retryAfter: rl.retryAfterSec }, 429);
    }
    const session = pendingOAuth.get(sessionId);
    if (!session || session.ownerId !== user.id) return c.json({ status: "not_found" }, 404);
    return c.json({
      provider: session.provider,
      status: session.status,
      error: session.error,
      accountLabel: session.accountLabel,
    });
  });

  // UI: Dashboard (Server-Side Rendered on First Paint)
  app.get("/", c => {
    const user = c.get("user");
    const latest = vault.getLatestUsage(user.id);
    const creds = vault.listCredentials(user.id);
    const credsMap = new Map(creds.map(cr => [cr.id, cr]));
    const enriched: (UsageReport & { createdAt?: number; accent?: string | null; metadata?: Record<string, unknown> })[] = latest.map(r => {
      const cr = r.credentialId ? credsMap.get(r.credentialId) : undefined;
      const accent = cr?.accent || "default";
      return {
        ...r,
        accountLabel: cr?.accountLabel || r.accountLabel,
        createdAt: cr?.createdAt,
        accent,
        metadata: cr?.metadata,
      };
    });
    return c.html(renderDashboardHtml(enriched, user));
  });

  return app;
}

function formatProviderTitle(provider: string): string {
  const p = (provider || "").toLowerCase();
  if (p === "antigravity" || p === "google-antigravity" || p === "google") return "Antigravity";
  if (p === "openai-codex" || p === "codex") return "OpenAI Codex";
  if (p === "openrouter") return "OpenRouter";
  if (p === "deepseek") return "DeepSeek";
  if (p === "anthropic" || p === "claude") return "Anthropic Claude";
  if (p === "cursor") return "Cursor";
  if (p === "github-copilot" || p === "copilot") return "GitHub Copilot";
  if (p === "xai-oauth" || p === "grok" || p === "xai") return "xAI Grok";
  if (p === "zai" || p === "zhipu" || p === "glm") return "Zhipu AI (GLM)";
  if (p === "minimax-code" || p === "minimax") return "MiniMax Code";
  if (p === "cline-pass" || p === "clinepass") return "Cline Pass";
  if (p === "devin") return "Devin";
  if (p === "umans") return "Umans";
  if (p === "google-gemini-cli" || p === "gemini-cli") return "Gemini CLI";
  if (p === "kimi-code" || p === "kimi" || p === "moonshot") return "Kimi Code";
  if (p === "opencode-go") return "OpenCode Go";
  if (p === "alibaba-token-plan") return "Alibaba Qwen";
  return provider.charAt(0).toUpperCase() + provider.slice(1);
}

function escapeHtml(str: string): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderAuthPageHtml(options: { mode: "login" | "register"; registrationDisabled?: boolean }): string {
  const isLogin = options.mode === "login";
  const isRegDisabled = !isLogin && Boolean(options.registrationDisabled);
  const initialTitle = isRegDisabled ? "Kayıtlar Kapalı | useMeter" : isLogin ? "Giriş Yap | useMeter" : "Hesap Oluştur | useMeter";
  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${initialTitle}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            appBg: 'var(--color-bg)',
            appSurface: 'var(--color-surface)',
            appBorder: 'var(--color-border)',
            appMuted: 'var(--color-muted)',
            appAccent: 'var(--color-accent)',
            appAccentHover: 'var(--color-accent-hover)',
            appAccentSoft: 'var(--color-accent-soft)',
            appText: 'var(--color-text)',
            appTextMuted: 'var(--color-text-muted)'
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --color-bg: #090a0d;
      --color-surface: #111318;
      --color-border: #1f232b;
      --color-muted: #171a21;
      --color-text: #f4f4f6;
      --color-text-muted: #8e95a5;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-soft: rgba(255, 152, 73, 0.12);
    }
    html.light {
      --color-bg: #f8fafc;
      --color-surface: #ffffff;
      --color-border: #e2e8f0;
      --color-muted: #f1f5f9;
      --color-text: #0f172a;
      --color-text-muted: #64748b;
      --color-accent: #ea580c;
      --color-accent-hover: #c2410c;
      --color-accent-soft: rgba(234, 88, 12, 0.1);
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col transition-colors duration-200 text-sm">
  <header class="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-4 sm:px-6 py-4 sticky top-0 z-20">
    <div class="max-w-7xl mx-auto flex items-center justify-between">
      <a href="/" class="flex items-center gap-2">
        <span class="font-extrabold tracking-wider text-appText text-lg font-mono">use<span class="text-appAccent">Meter</span></span>
        <span class="w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20"></span>
      </a>
      <div class="flex items-center gap-2">
        <button type="button" onclick="toggleLightDark()" id="lightDarkBtn" title="Theme" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <span id="lightDarkIcon">☀️</span>
        </button>
        <button type="button" onclick="toggleLang()" id="langBtn" class="h-9 px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent/50 transition flex items-center gap-2">
          <span id="langFlag" class="text-base">🇹🇷</span>
          <span id="langLabel">TR</span>
        </button>
      </div>
    </div>
  </header>

  <main class="flex-1 flex items-center justify-center px-4 py-12">
    <div class="w-full max-w-md border border-appBorder bg-appSurface rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
      <div class="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-appAccent to-transparent opacity-60"></div>
      
      ${isRegDisabled ? `
      <div class="mb-6">
        <div class="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center text-xl mb-4">
          🔒
        </div>
        <h1 class="text-xl font-bold text-appText" id="authTitle" data-i18n="authRegDisabledTitle">
          Kayıtlar Kapalı
        </h1>
        <p class="text-xs text-appTextMuted mt-2 leading-relaxed" id="authSubtitle" data-i18n="authRegDisabledDesc">
          Yeni kullanıcı kayıtları sistem yöneticisi tarafından kapatılmıştır. Registration is disabled by administrator.
        </p>
      </div>

      <div class="pt-2">
        <a href="/login" class="w-full py-2.5 px-4 rounded-lg bg-appAccent hover:bg-appAccentHover text-zinc-950 text-sm font-bold transition flex items-center justify-center gap-2 shadow-sm" data-i18n="authToLoginBtn">
          Giriş Yap
        </a>
      </div>

      <div class="mt-6 pt-4 border-t border-appBorder text-center text-xs text-appTextMuted">
        <a href="/login" class="font-semibold text-appAccent hover:underline" data-i18n="authToLogin">Giriş Yapın</a>
      </div>
      ` : `
      <div class="mb-6">
        <h1 class="text-xl font-bold text-appText" id="authTitle" data-i18n="${isLogin ? "authLoginTitle" : "authRegisterTitle"}">
          ${isLogin ? "Giriş Yap" : "Hesap Oluştur"}
        </h1>
        <p class="text-xs text-appTextMuted mt-1" id="authSubtitle" data-i18n="${isLogin ? "authLoginSubtitle" : "authRegisterSubtitle"}">
          ${isLogin ? "AI Kullanım Takip Paneline erişmek için giriş yapın." : "AI kotalarınızı ve bakiyelerinizi takip etmek için yeni hesap açın."}
        </p>
      </div>

      <div id="authError" class="hidden mb-4 p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs"></div>

      <form id="authForm" onsubmit="handleAuthSubmit(event)" class="space-y-4">
        <div>
          <label for="email" class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="authEmail">E-posta</label>
          <input type="email" id="email" name="email" required autocomplete="email" placeholder="name@example.com" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent focus:outline-none transition" />
        </div>

        <div>
          <label for="password" class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="authPassword">Şifre</label>
          <input type="password" id="password" name="password" required autocomplete="${isLogin ? "current-password" : "new-password"}" placeholder="••••••••••••" minlength="${isLogin ? "1" : "12"}" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent focus:outline-none transition" />
          ${!isLogin ? '<p class="text-[11px] text-appTextMuted mt-1" data-i18n="authPasswordHelp">En az 12 karakter olmalıdır.</p>' : ""}
        </div>

        ${!isLogin ? `
        <div>
          <label for="confirmPassword" class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="authConfirmPassword">Şifre Tekrarı</label>
          <input type="password" id="confirmPassword" name="confirmPassword" required autocomplete="new-password" placeholder="••••••••••••" minlength="12" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent focus:outline-none transition" />
        </div>
        ` : ""}

        <div class="pt-2">
          <button type="submit" id="submitBtn" class="w-full py-2.5 px-4 rounded-lg bg-appAccent hover:bg-appAccentHover text-zinc-950 text-sm font-bold transition flex items-center justify-center gap-2 shadow-sm cursor-pointer">
            <span id="submitSpinner" class="hidden animate-spin w-4 h-4 border-2 border-zinc-950 border-t-transparent rounded-full"></span>
            <span id="submitText" data-i18n="${isLogin ? "authLoginBtn" : "authRegisterBtn"}">${isLogin ? "Giriş Yap" : "Kayıt Ol"}</span>
          </button>
        </div>
      </form>

      <div class="mt-6 pt-4 border-t border-appBorder text-center text-xs text-appTextMuted">
        ${isLogin
          ? '<span data-i18n="authNoAccount">Hesabınız yok mu?</span> <a href="/register" class="font-semibold text-appAccent hover:underline" data-i18n="authToRegister">Kayıt Olun</a>'
          : '<span data-i18n="authHasAccount">Zaten hesabınız var mı?</span> <a href="/login" class="font-semibold text-appAccent hover:underline" data-i18n="authToLogin">Giriş Yapın</a>'}
      </div>
      `}
  </main>

  <script>
    const I18N_AUTH = {
      tr: {
        authLoginTitle: "Giriş Yap",
        authLoginSubtitle: "AI Kullanım Takip Paneline erişmek için giriş yapın.",
        authRegisterTitle: "Hesap Oluştur",
        authRegisterSubtitle: "AI kotalarınızı ve bakiyelerinizi takip etmek için yeni hesap açın.",
        authEmail: "E-posta",
        authPassword: "Şifre",
        authConfirmPassword: "Şifre Tekrarı",
        authPasswordHelp: "En az 12 karakter olmalıdır.",
        authLoginBtn: "Giriş Yap",
        authRegisterBtn: "Kayıt Ol",
        authNoAccount: "Hesabınız yok mu?",
        authToRegister: "Kayıt Olun",
        authHasAccount: "Zaten hesabınız var mı?",
        authToLogin: "Giriş Yapın",
        authPasswordMismatch: "Şifreler birbiriyle eşleşmiyor.",
        authPasswordTooShort: "Şifre en az 12 karakter olmalıdır.",
        authInvalidEmail: "Lütfen geçerli bir e-posta adresi girin.",
        authGeneralError: "İşlem sırasında bir hata oluştu.",
        authRegDisabledTitle: "Kayıtlar Kapalı",
        authRegDisabledDesc: "Yeni kullanıcı kayıtları sistem yöneticisi tarafından kapatılmıştır. Registration is disabled by administrator.",
        authToLoginBtn: "Giriş Yap",
        flag: "🇹🇷"
      },
      en: {
        authLoginTitle: "Sign In",
        authLoginSubtitle: "Sign in to access your AI Usage & Quota dashboard.",
        authRegisterTitle: "Create Account",
        authRegisterSubtitle: "Register to start tracking your AI quotas and balances.",
        authEmail: "Email address",
        authPassword: "Password",
        authConfirmPassword: "Confirm Password",
        authPasswordHelp: "Must be at least 12 characters.",
        authLoginBtn: "Sign In",
        authRegisterBtn: "Create Account",
        authNoAccount: "Don't have an account?",
        authToRegister: "Sign Up",
        authHasAccount: "Already have an account?",
        authToLogin: "Sign In",
        authPasswordMismatch: "Passwords do not match.",
        authPasswordTooShort: "Password must be at least 12 characters.",
        authInvalidEmail: "Please enter a valid email address.",
        authGeneralError: "An error occurred during request.",
        authRegDisabledTitle: "Registration Disabled",
        authRegDisabledDesc: "Registration is disabled by administrator. If you already have an account, please sign in.",
        authToLoginBtn: "Sign In",
        flag: "🇬🇧"
      }
    };

    function detectLang() {
      const saved = localStorage.getItem('usage_lang');
      if (saved === 'tr' || saved === 'en') return saved;
      const browserLang = (navigator.language || '').toLowerCase();
      return browserLang.startsWith('tr') ? 'tr' : 'en';
    }

    let currentLang = detectLang();
    let currentMode = localStorage.getItem('usage_mode') || 'dark';

    function t(key) {
      return (I18N_AUTH[currentLang] && I18N_AUTH[currentLang][key]) || (I18N_AUTH['tr'][key]) || key;
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key && t(key)) el.textContent = t(key);
      });
      const flagEl = document.getElementById('langFlag');
      const labelEl = document.getElementById('langLabel');
      if (flagEl) flagEl.textContent = currentLang === 'tr' ? '🇹🇷' : '🇬🇧';
      if (labelEl) labelEl.textContent = currentLang.toUpperCase();
      const pageTitleKey = ${isRegDisabled ? '"authRegDisabledTitle"' : isLogin ? '"authLoginTitle"' : '"authRegisterTitle"'};
      document.title = (t(pageTitleKey) || "useMeter") + " | useMeter";
    }

    function toggleLang() {
      currentLang = currentLang === 'tr' ? 'en' : 'tr';
      localStorage.setItem('usage_lang', currentLang);
      applyI18n();
    }

    function applyTheme() {
      const html = document.documentElement;
      const icon = document.getElementById('lightDarkIcon');
      if (currentMode === 'light') {
        html.classList.remove('dark');
        html.classList.add('light');
        if (icon) icon.textContent = '🌙';
      } else {
        html.classList.remove('light');
        html.classList.add('dark');
        if (icon) icon.textContent = '☀️';
      }
    }

    function toggleLightDark() {
      currentMode = currentMode === 'light' ? 'dark' : 'light';
      localStorage.setItem('usage_mode', currentMode);
      applyTheme();
    }

    applyTheme();
    applyI18n();

    async function handleAuthSubmit(e) {
      e.preventDefault();
      const errBox = document.getElementById('authError');
      errBox.classList.add('hidden');
      errBox.textContent = '';

      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const isLoginMode = ${isLogin};

      if (!isLoginMode) {
        const confirmPassword = document.getElementById('confirmPassword').value;
        if (password.length < 12) {
          errBox.textContent = t('authPasswordTooShort');
          errBox.classList.remove('hidden');
          return;
        }
        if (password !== confirmPassword) {
          errBox.textContent = t('authPasswordMismatch');
          errBox.classList.remove('hidden');
          return;
        }
      }

      const submitBtn = document.getElementById('submitBtn');
      const submitSpinner = document.getElementById('submitSpinner');
      submitBtn.disabled = true;
      submitSpinner.classList.remove('hidden');

      try {
        const endpoint = isLoginMode ? '/api/auth/login' : '/api/auth/register';
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.success === false) {
          errBox.textContent = data.error || data.message || t('authGeneralError');
          errBox.classList.remove('hidden');
          submitBtn.disabled = false;
          submitSpinner.classList.add('hidden');
          return;
        }
        window.location.href = '/';
      } catch (err) {
        errBox.textContent = t('authGeneralError');
        errBox.classList.remove('hidden');
        submitBtn.disabled = false;
        submitSpinner.classList.add('hidden');
      }
    }
  </script>
</body>
</html>`;
}
export function renderInvitePageHtml(options: { token: string }): string {
  const token = options.token || "";
  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Daveti Kabul Et | useMeter</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            appBg: 'var(--color-bg)',
            appSurface: 'var(--color-surface)',
            appBorder: 'var(--color-border)',
            appMuted: 'var(--color-muted)',
            appAccent: 'var(--color-accent)',
            appAccentHover: 'var(--color-accent-hover)',
            appAccentSoft: 'var(--color-accent-soft)',
            appText: 'var(--color-text)',
            appTextMuted: 'var(--color-text-muted)'
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --color-bg: #090a0d;
      --color-surface: #111318;
      --color-border: #1f232b;
      --color-muted: #171a21;
      --color-text: #f4f4f6;
      --color-text-muted: #8e95a5;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-soft: rgba(255, 152, 73, 0.12);
    }
    html.light {
      --color-bg: #f8fafc;
      --color-surface: #ffffff;
      --color-border: #e2e8f0;
      --color-muted: #f1f5f9;
      --color-text: #0f172a;
      --color-text-muted: #64748b;
      --color-accent: #ea580c;
      --color-accent-hover: #c2410c;
      --color-accent-soft: rgba(234, 88, 12, 0.1);
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col transition-colors duration-200 text-sm">
  <header class="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-4 sm:px-6 py-4 sticky top-0 z-20">
    <div class="max-w-7xl mx-auto flex items-center justify-between">
      <a href="/" class="flex items-center gap-2">
        <span class="font-extrabold tracking-wider text-appText text-lg font-mono">use<span class="text-appAccent">Meter</span></span>
        <span class="w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20"></span>
      </a>
      <div class="flex items-center gap-2">
        <button type="button" onclick="toggleLightDark()" id="lightDarkBtn" title="Theme" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <span id="lightDarkIcon">☀️</span>
        </button>
        <button type="button" onclick="toggleLang()" id="langBtn" class="h-9 px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent/50 transition flex items-center gap-2">
          <span id="langFlag" class="text-base">🇹🇷</span>
          <span id="langLabel">TR</span>
        </button>
      </div>
    </div>
  </header>

  <main class="flex-1 flex items-center justify-center px-4 py-12">
    <div class="w-full max-w-md border border-appBorder bg-appSurface rounded-2xl p-6 sm:p-8 shadow-xl space-y-6">
      <div class="space-y-2 text-center">
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold font-mono bg-appAccentSoft text-appAccent border border-appAccent/20">
          <span>✉️</span>
          <span data-i18n="badgeInvite">Özel Davet</span>
        </div>
        <h1 class="text-xl font-bold text-appText tracking-tight" data-i18n="inviteTitle">Daveti Kabul Et</h1>
        <p class="text-xs text-appTextMuted" data-i18n="inviteDesc">useMeter hesabınızı etkinleştirmek için en az 12 karakterlik güvenli bir parola belirleyin.</p>
      </div>

      <form id="acceptInviteForm" onsubmit="handleAcceptInvite(event)" class="space-y-4">
        <input type="hidden" id="inviteToken" value="${escapeHtml(token)}">
        <div>
          <label class="block text-xs font-medium text-appTextMuted mb-1.5 font-mono" data-i18n="labelPassword">Yeni Parola</label>
          <input type="password" id="passwordInput" required minlength="12" maxlength="256" autocomplete="new-password" placeholder="••••••••••••" class="w-full px-3.5 py-2.5 rounded-xl border border-appBorder bg-appBg text-appText text-xs font-mono focus:border-appAccent focus:outline-hidden transition">
          <p class="text-[11px] text-appTextMuted font-mono mt-1" data-i18n="passwordHint">En az 12 karakter olmalıdır.</p>
        </div>

        <div>
          <label class="block text-xs font-medium text-appTextMuted mb-1.5 font-mono" data-i18n="labelPasswordConfirm">Parola Tekrar</label>
          <input type="password" id="passwordConfirmInput" required minlength="12" maxlength="256" autocomplete="new-password" placeholder="••••••••••••" class="w-full px-3.5 py-2.5 rounded-xl border border-appBorder bg-appBg text-appText text-xs font-mono focus:border-appAccent focus:outline-hidden transition">
        </div>

        <div id="formError" class="hidden text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-lg p-3 font-mono"></div>

        <button type="submit" id="submitBtn" class="w-full py-2.5 px-4 rounded-xl text-xs font-bold bg-appAccent text-black hover:bg-appAccentHover transition font-mono cursor-pointer flex items-center justify-center gap-2 shadow-xs">
          <span id="submitSpinner" class="hidden animate-spin w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full"></span>
          <span id="submitText" data-i18n="btnActivate">Hesabı Etkinleştir & Giriş Yap</span>
        </button>
      </form>
    </div>
  </main>

  <script>
    const I18N = {
      tr: {
        flag: "🇹🇷",
        badgeInvite: "Özel Davet",
        inviteTitle: "Daveti Kabul Et",
        inviteDesc: "useMeter hesabınızı etkinleştirmek için en az 12 karakterlik güvenli bir parola belirleyin.",
        labelPassword: "Yeni Parola",
        labelPasswordConfirm: "Parola Tekrar",
        passwordHint: "En az 12 karakter olmalıdır.",
        btnActivate: "Hesabı Etkinleştir & Giriş Yap",
        errMismatch: "Girdiğiniz parolalar birbiriyle eşleşmiyor.",
        errLength: "Parola en az 12 karakter uzunluğunda olmalıdır.",
        errGeneric: "Geçersiz veya süresi dolmuş davet bağlantısı.",
        errNetwork: "Bağlantı hatası. Lütfen tekrar deneyin."
      },
      en: {
        flag: "🇬🇧",
        badgeInvite: "Private Invitation",
        inviteTitle: "Accept Invitation",
        inviteDesc: "Set a secure password of at least 12 characters to activate your useMeter account.",
        labelPassword: "New Password",
        labelPasswordConfirm: "Confirm Password",
        passwordHint: "Must be at least 12 characters.",
        btnActivate: "Activate Account & Sign In",
        errMismatch: "Passwords do not match.",
        errLength: "Password must be at least 12 characters long.",
        errGeneric: "Invalid or expired invitation link.",
        errNetwork: "Network error. Please try again."
      }
    };

    let currentLang = localStorage.getItem('usage_lang') || 'tr';
    let currentMode = localStorage.getItem('usage_mode') || 'dark';

    function t(key) {
      return (I18N[currentLang] && I18N[currentLang][key]) || (I18N['tr'][key]) || key;
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key) el.innerHTML = t(key);
      });
      const flagEl = document.getElementById('langFlag');
      if (flagEl && I18N[currentLang]) flagEl.innerText = I18N[currentLang].flag;
      const labelEl = document.getElementById('langLabel');
      if (labelEl) labelEl.innerText = currentLang.toUpperCase();
    }

    function toggleLang() {
      currentLang = currentLang === 'tr' ? 'en' : 'tr';
      localStorage.setItem('usage_lang', currentLang);
      applyI18n();
    }

    function applyLightDarkMode(mode) {
      currentMode = mode;
      localStorage.setItem('usage_mode', mode);
      const isDark = mode === 'dark';
      document.documentElement.classList.toggle('dark', isDark);
      document.documentElement.classList.toggle('light', !isDark);
      const icon = document.getElementById('lightDarkIcon');
      if (icon) icon.innerText = isDark ? '☀️' : '🌙';
    }

    function toggleLightDark() {
      applyLightDarkMode(currentMode === 'dark' ? 'light' : 'dark');
    }

    async function handleAcceptInvite(e) {
      e.preventDefault();
      const token = document.getElementById('inviteToken').value.trim();
      const password = document.getElementById('passwordInput').value;
      const confirm = document.getElementById('passwordConfirmInput').value;
      const errorEl = document.getElementById('formError');
      const spinner = document.getElementById('submitSpinner');
      const submitBtn = document.getElementById('submitBtn');

      errorEl.classList.add('hidden');
      if (!token) {
        errorEl.innerText = t('errGeneric');
        errorEl.classList.remove('hidden');
        return;
      }
      if (password !== confirm) {
        errorEl.innerText = t('errMismatch');
        errorEl.classList.remove('hidden');
        return;
      }
      if (password.length < 12) {
        errorEl.innerText = t('errLength');
        errorEl.classList.remove('hidden');
        return;
      }

      spinner.classList.remove('hidden');
      submitBtn.disabled = true;

      try {
        const res = await fetch('/api/invitations/' + encodeURIComponent(token) + '/accept', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          errorEl.innerText = data.error || t('errGeneric');
          errorEl.classList.remove('hidden');
          return;
        }
        window.location.href = '/';
      } catch (err) {
        errorEl.innerText = t('errNetwork');
        errorEl.classList.remove('hidden');
      } finally {
        spinner.classList.add('hidden');
        submitBtn.disabled = false;
      }
    }

    applyLightDarkMode(currentMode);
    applyI18n();
  </script>
</body>
</html>`;
}

function renderAdminForbiddenHtml(): string {
  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 - Erişim Yetkiniz Yok | useMeter</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --color-bg: #090a0d;
      --color-surface: #111318;
      --color-border: #1f232b;
      --color-text: #f4f4f6;
      --color-text-muted: #8e95a5;
      --color-accent: #ff9849;
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
  <div class="max-w-md w-full border border-rose-500/30 bg-[#111318] rounded-2xl p-8 text-center space-y-4 shadow-xl">
    <div class="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 mx-auto flex items-center justify-center text-xl font-bold font-mono">!</div>
    <h1 class="text-lg font-bold text-[#f4f4f6]">403 - Erişim Yetkiniz Yok / Forbidden: Admin Access Required</h1>
    <p class="text-xs text-[#8e95a5] leading-relaxed">Bu yönetim paneline ve sistem ayarlarına erişmek için yönetici (admin) rolüne sahip olmanız gerekmektedir.</p>
    <div class="pt-4">
      <a href="/" class="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#1f232b] hover:bg-[#2a303c] text-[#f4f4f6] transition border border-[#1f232b]">
        &larr; Panoya Dön / Back to Dashboard
      </a>
    </div>
  </div>
</body>
</html>`;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(timestamp: number): string {
  if (!timestamp) return "-";
  const d = new Date(timestamp);
  return d.toISOString().replace("T", " ").substring(0, 16);
}

function renderAdminDashboardHtml(params: {
  user: User;
  stats: AdminSystemStats;
  users: AdminUserView[];
  invitations?: InvitationView[];
}): string {
  const { user, stats, users, invitations = [] } = params;
  const totalAdmins = users.filter(u => u.role === "admin").length;

  const providerEntries = Object.entries(stats.providerCounts || {});
  const providerPillsHtml = providerEntries.length === 0
    ? `<span class="text-xs text-appTextMuted italic" data-i18n="noProviders">Henüz kayıtlı bir sağlayıcı hesabı yok.</span>`
    : providerEntries.map(([provider, count]) => `
        <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl border border-appBorder bg-appSurface text-xs transition hover:border-appAccent/40">
          <span class="font-medium text-appText font-mono">${escapeHtml(formatProviderTitle(provider))}</span>
          <span class="px-2 py-0.5 rounded-md bg-appAccentSoft text-appAccent font-bold font-mono text-[11px] border border-appAccent/20">${count}</span>
        </div>
      `).join("");

  const userRowsHtml = users.map(u => {
    const isSelf = u.id === user.id;
    const isLastAdmin = u.role === "admin" && totalAdmins <= 1;

    const roleBadge = u.role === "admin"
      ? `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 font-mono">Admin</span>`
      : `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-300 border border-slate-500/30 font-mono">User</span>`;

    let roleBtnHtml = "";
    if (u.role === "admin") {
      if (isSelf) {
        roleBtnHtml = `<button disabled title="Kendi rolünüzü değiştiremezsiniz / Cannot demote self" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-appBorder text-appTextMuted opacity-40 cursor-not-allowed font-mono">Rolü Al</button>`;
      } else if (isLastAdmin) {
        roleBtnHtml = `<button disabled title="Sistemdeki son yönetici indirgenemez / Cannot demote the last admin" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-appBorder text-appTextMuted opacity-40 cursor-not-allowed font-mono">Rolü Al</button>`;
      } else {
        roleBtnHtml = `<button type="button" onclick="updateRole('${u.id}', 'user')" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 transition font-mono cursor-pointer" data-i18n="btnDemote">Kullanıcı Yap</button>`;
      }
    } else {
      roleBtnHtml = `<button type="button" onclick="updateRole('${u.id}', 'admin')" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 transition font-mono cursor-pointer" data-i18n="btnPromote">Yönetici Yap</button>`;
    }

    let deleteBtnHtml = "";
    if (isSelf) {
      deleteBtnHtml = `<button disabled title="Kendi hesabınızı silemezsiniz / Cannot delete own account" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-appBorder text-appTextMuted opacity-40 cursor-not-allowed font-mono">Sil</button>`;
    } else if (isLastAdmin) {
      deleteBtnHtml = `<button disabled title="Sistemdeki son yönetici silinemez / Cannot delete the last admin" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-appBorder text-appTextMuted opacity-40 cursor-not-allowed font-mono">Sil</button>`;
    } else {
      deleteBtnHtml = `<button type="button" onclick="deleteUser('${u.id}', '${escapeHtml(u.email)}')" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-rose-500/40 text-rose-400 hover:bg-rose-500/10 transition font-mono cursor-pointer" data-i18n="btnDelete">Sil</button>`;
    }

    return `
      <tr class="hover:bg-appMuted/30 transition">
        <td class="px-5 py-3.5">
          <div class="flex items-center gap-2">
            <span class="font-medium text-appText font-mono">${escapeHtml(u.email)}</span>
            ${isSelf ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-appAccentSoft text-appAccent border border-appAccent/30 font-mono">SİZ</span>` : ""}
          </div>
          <span class="text-[11px] text-appTextMuted font-mono block mt-0.5">ID: ${escapeHtml(u.id)}</span>
        </td>
        <td class="px-4 py-3.5">${roleBadge}</td>
        <td class="px-4 py-3.5 text-center font-mono font-semibold text-appText">${u.credentialCount}</td>
        <td class="px-4 py-3.5 text-center font-mono font-semibold text-appText">${u.activeSessionCount}</td>
        <td class="px-4 py-3.5 font-mono text-appTextMuted">${formatDate(u.createdAt)}</td>
        <td class="px-5 py-3.5 text-right">
          <div class="flex items-center justify-end gap-2">
            ${roleBtnHtml}
            ${deleteBtnHtml}
          </div>
        </td>
      </tr>
    `;
  }).join("");
  const now = Date.now();
  const invitationRowsHtml = (invitations.length === 0)
    ? `<tr><td colspan="5" class="px-5 py-6 text-center text-xs text-appTextMuted italic" data-i18n="noInvitations">Henüz oluşturulmuş bir davet bulunmuyor.</td></tr>`
    : invitations.map(inv => {
        let statusBadge = "";
        const isExpired = inv.status === "pending" && inv.expiresAt < now;
        const effectiveStatus = isExpired ? "expired" : inv.status;

        if (effectiveStatus === "accepted") {
          statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono" data-i18n="statusAccepted">Kabul Edildi</span>`;
        } else if (effectiveStatus === "revoked") {
          statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-zinc-500/10 text-zinc-400 border border-zinc-500/20 font-mono" data-i18n="statusRevoked">İptal Edildi</span>`;
        } else if (effectiveStatus === "expired") {
          statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono" data-i18n="statusExpired">Süresi Doldu</span>`;
        } else {
          statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono" data-i18n="statusPending">Bekliyor</span>`;
        }

        let revokeBtnHtml = "";
        if (inv.status === "pending" && !isExpired) {
          revokeBtnHtml = `<button type="button" onclick="revokeInvitation('${inv.id}', '${escapeHtml(inv.email)}')" class="px-2.5 py-1 rounded-lg text-xs font-semibold border border-rose-500/40 text-rose-400 hover:bg-rose-500/10 transition font-mono cursor-pointer" data-i18n="btnRevoke">İptal Et</button>`;
        } else {
          revokeBtnHtml = `<span class="text-appTextMuted text-[11px] font-mono">—</span>`;
        }

        return `
          <tr class="hover:bg-appMuted/30 transition">
            <td class="px-5 py-3.5">
              <span class="font-medium text-appText font-mono">${escapeHtml(inv.email)}</span>
            </td>
            <td class="px-4 py-3.5">${statusBadge}</td>
            <td class="px-4 py-3.5 font-mono text-appTextMuted">${formatDate(inv.expiresAt)}</td>
            <td class="px-4 py-3.5 font-mono text-appTextMuted">${formatDate(inv.createdAt)}</td>
            <td class="px-5 py-3.5 text-right">
              ${revokeBtnHtml}
            </td>
          </tr>
        `;
      }).join("");

  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Yönetim Paneli | useMeter [ADMIN]</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            appBg: 'var(--color-bg)',
            appSurface: 'var(--color-surface)',
            appBorder: 'var(--color-border)',
            appMuted: 'var(--color-muted)',
            appAccent: 'var(--color-accent)',
            appAccentHover: 'var(--color-accent-hover)',
            appAccentSoft: 'var(--color-accent-soft)',
            appText: 'var(--color-text)',
            appTextMuted: 'var(--color-text-muted)'
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --color-bg: #090a0d;
      --color-surface: #111318;
      --color-border: #1f232b;
      --color-muted: #171a21;
      --color-text: #f4f4f6;
      --color-text-muted: #8e95a5;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-soft: rgba(255, 152, 73, 0.12);
    }
    html.light {
      --color-bg: #f8fafc;
      --color-surface: #ffffff;
      --color-border: #e2e8f0;
      --color-muted: #f1f5f9;
      --color-text: #0f172a;
      --color-text-muted: #64748b;
      --color-accent: #ea580c;
      --color-accent-hover: #c2410c;
      --color-accent-soft: rgba(234, 88, 12, 0.1);
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col bg-appBg text-appText">
  <!-- Top Header Navigation -->
  <header class="border-b border-appBorder bg-appSurface/80 backdrop-blur-md sticky top-0 z-30 px-4 sm:px-6 py-3">
    <div class="max-w-screen-2xl mx-auto flex items-center justify-between gap-4">
      <!-- Left Logo & Back Link -->
      <div class="flex items-center gap-2 sm:gap-3">
        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" title="System Operational"></span>
        <span class="font-extrabold tracking-wider text-base text-appText font-mono">use<span class="text-appAccent">Meter</span></span>
        <span class="px-2 py-0.5 text-[11px] font-extrabold uppercase tracking-wider rounded-md bg-amber-500/10 text-amber-500 border border-amber-500/30 font-mono">ADMIN</span>
        <a href="/" class="text-xs text-appTextMuted hover:text-appAccent transition flex items-center gap-1 border-l border-appBorder pl-2.5 sm:pl-3 ml-1">
          <span>&larr;</span>
          <span data-i18n="backToDashboard">Panoya Dön</span>
        </a>
      </div>

      <!-- Right Controls -->
      <div class="flex items-center gap-2 sm:gap-3">
        <!-- Dark / Light Mode Toggle -->
        <button onclick="toggleLightDark()" id="lightDarkBtn" title="Koyu / Aydınlık Mod" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm cursor-pointer">
          <span id="lightDarkIcon">☀️</span>
        </button>

        <!-- Language Switcher -->
        <button onclick="toggleLang()" id="langBtn" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent/50 transition flex items-center gap-1.5 cursor-pointer font-mono">
          <span id="langFlag" class="text-base">🇹🇷</span>
          <span id="langLabel">TR</span>
        </button>

        <!-- Active Admin Badge -->
        <div class="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg border border-appBorder bg-appSurface text-xs text-appText font-mono">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-amber-500">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span class="max-w-[150px] truncate hidden sm:inline-block" title="${escapeHtml(user.email)}">${escapeHtml(user.email)}</span>
        </div>

        <!-- Logout Button -->
        <button type="button" onclick="logoutUser()" id="logoutBtn" title="Oturumu Kapat" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-rose-400 hover:border-rose-500/50 transition flex items-center gap-1.5 text-xs font-semibold cursor-pointer">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          <span data-i18n="logoutText">Çıkış</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Content Container -->
  <main class="flex-1 max-w-screen-2xl w-full mx-auto p-4 sm:p-6 space-y-6">
    <!-- Page Title -->
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-appBorder pb-4">
      <div>
        <h1 class="text-xl font-bold text-appText tracking-tight flex items-center gap-2">
          <span data-i18n="adminPageTitle">Sistem Yönetim Merkezi</span>
        </h1>
        <p class="text-xs text-appTextMuted mt-1" data-i18n="adminPageDesc">Sistem geneli kullanıcı yönetimi, aktif oturumlar ve SQLite telemetrisi.</p>
      </div>
      <div class="text-xs font-mono text-appTextMuted flex items-center gap-2">
        <span class="w-2 h-2 rounded-full ${stats.integrity ? "bg-emerald-500" : "bg-rose-500"}"></span>
        <span>PRAGMA quick_check: <strong class="${stats.integrity ? "text-emerald-400" : "text-rose-400"}">${stats.integrity ? "OK" : "CORRUPT"}</strong></span>
      </div>
    </div>

    <!-- Summary KPI Strip -->
    <section class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
      <!-- Total Users -->
      <div class="border border-appBorder bg-appSurface rounded-xl p-4 space-y-1 shadow-xs">
        <span class="text-xs text-appTextMuted block truncate font-medium" data-i18n="summaryUsers">Toplam Kullanıcı</span>
        <span class="text-2xl font-bold text-appText font-mono block">${stats.totalUsers}</span>
      </div>

      <!-- Total Credentials -->
      <div class="border border-appBorder bg-appSurface rounded-xl p-4 space-y-1 shadow-xs">
        <span class="text-xs text-appTextMuted block truncate font-medium" data-i18n="summaryCredentials">Toplam Hesap</span>
        <span class="text-2xl font-bold text-appAccent font-mono block">${stats.totalCredentials}</span>
      </div>

      <!-- Total Snapshots -->
      <div class="border border-appBorder bg-appSurface rounded-xl p-4 space-y-1 shadow-xs">
        <span class="text-xs text-appTextMuted block truncate font-medium" data-i18n="summarySnapshots">Kota Geçmişi</span>
        <span class="text-2xl font-bold text-appText font-mono block">${stats.totalSnapshots}</span>
      </div>

      <!-- Active Sessions -->
      <div class="border border-appBorder bg-appSurface rounded-xl p-4 space-y-1 shadow-xs">
        <span class="text-xs text-appTextMuted block truncate font-medium" data-i18n="summarySessions">Aktif Oturum</span>
        <span class="text-2xl font-bold text-emerald-400 font-mono block">${stats.activeSessions}</span>
      </div>

      <!-- DB Size -->
      <div class="border border-appBorder bg-appSurface rounded-xl p-4 space-y-1 shadow-xs">
        <span class="text-xs text-appTextMuted block truncate font-medium" data-i18n="summaryDbSize">Veritabanı Boyutu</span>
        <span class="text-xl font-bold text-appText font-mono block">${formatBytes(stats.databaseSizeBytes)}</span>
      </div>

      <!-- Poller Status -->
      <div class="border border-appBorder bg-appSurface rounded-xl p-4 space-y-1 shadow-xs flex flex-col justify-between">
        <span class="text-xs text-appTextMuted block truncate font-medium" data-i18n="summaryPoller">Daemon Poller</span>
        <div class="pt-1">
          ${stats.pollerRunning
            ? `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span><span data-i18n="pollerRunning">Çalışıyor</span></span>`
            : `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-zinc-500/10 text-zinc-400 border border-zinc-500/20 font-mono"><span class="w-1.5 h-1.5 rounded-full bg-zinc-500"></span><span data-i18n="pollerStopped">Durduruldu</span></span>`}
        </div>
      </div>
    </section>

    <!-- Provider Distribution Section -->
    <section class="border border-appBorder bg-appSurface/50 rounded-2xl p-5 space-y-3 shadow-xs">
      <div class="flex items-center justify-between">
        <div>
          <h2 class="text-sm font-bold text-appText" data-i18n="providerDistTitle">Sağlayıcı Hesap Dağılımı</h2>
          <p class="text-xs text-appTextMuted mt-0.5" data-i18n="providerDistDesc">Sistem genelinde tüm kullanıcılar tarafından bağlanan hesap sayıları.</p>
        </div>
        <span class="px-2 py-0.5 rounded-md bg-appMuted text-appText font-mono text-xs font-semibold border border-appBorder">${providerEntries.length} Sağlayıcı</span>
      </div>
      <div class="flex flex-wrap gap-2 pt-1">
        ${providerPillsHtml}
      </div>
    </section>
    <!-- Registration Policy Section -->
    <section class="border border-appBorder bg-appSurface rounded-2xl p-5 shadow-xs">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div class="space-y-1">
          <div class="flex items-center gap-2.5">
            <h2 class="text-sm font-bold text-appText" data-i18n="regPolicyTitle">Kayıt Politikası</h2>
            <span id="regStatusBadge" class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold font-mono ${stats.allowRegistration ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border border-rose-500/20"}">
              <span class="w-1.5 h-1.5 rounded-full ${stats.allowRegistration ? "bg-emerald-400" : "bg-rose-400"}"></span>
              <span data-i18n="${stats.allowRegistration ? "regStatusOpen" : "regStatusClosed"}">${stats.allowRegistration ? "Açık" : "Kapalı"}</span>
            </span>
          </div>
          <p class="text-xs text-appTextMuted" id="regPolicyDesc" data-i18n="${stats.allowRegistration ? "regPolicyDescOpen" : "regPolicyDescClosed"}">
            ${stats.allowRegistration
              ? "Açık (Yeni kullanıcılar kayıt olabilir)"
              : "Kapalı (Yalnızca yöneticiler davet edebilir/mevcut kullanıcılar erişebilir)"}
          </p>
        </div>
        <div>
          <button type="button" id="regToggleBtn" onclick="toggleRegistration(${!stats.allowRegistration})" class="px-4 py-2 rounded-xl text-xs font-bold font-mono transition flex items-center gap-2 cursor-pointer shadow-xs ${stats.allowRegistration ? "border border-amber-500/40 text-amber-400 hover:bg-amber-500/10" : "border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"}">
            <span id="regToggleSpinner" class="hidden animate-spin w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full"></span>
            <span id="regToggleText" data-i18n="${stats.allowRegistration ? "btnDisableRegistration" : "btnEnableRegistration"}">${stats.allowRegistration ? "Kayıtları Kapat" : "Kayıtları Aç"}</span>
          </button>
        </div>
      </div>
    </section>


    <!-- Invitation Management Section -->
    <section class="border border-appBorder bg-appSurface rounded-2xl overflow-hidden shadow-xs">
      <div class="p-5 border-b border-appBorder flex flex-wrap items-center justify-between gap-3">
        <div>
          <div class="flex items-center gap-2.5">
            <h2 class="text-base font-bold text-appText tracking-tight" data-i18n="invitationMgmtTitle">Davet Yönetimi</h2>
            <span class="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-appAccentSoft text-appAccent border border-appAccent/20 font-mono">${invitations.length} <span data-i18n="invitationCountSuffix">Davet</span></span>
          </div>
          <p class="text-xs text-appTextMuted mt-0.5" data-i18n="invitationMgmtDesc">Kullanıcı davet bağlantıları oluşturun, durumlarını izleyin veya iptal edin.</p>
        </div>
        <button type="button" onclick="openInviteModal()" class="px-3.5 py-1.5 rounded-xl text-xs font-bold font-mono transition flex items-center gap-2 cursor-pointer shadow-xs bg-appAccent text-black hover:bg-appAccentHover">
          <span>+</span>
          <span data-i18n="btnNewInvite">Yeni Davet Oluştur</span>
        </button>
      </div>

      <!-- Created Invite Alert Box (hidden by default) -->
      <div id="createdInviteAlert" class="hidden m-5 p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-2">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2 text-emerald-400 font-semibold text-xs font-mono">
            <span>✓</span>
            <span data-i18n="inviteCreatedSuccess">Davet bağlantısı oluşturuldu!</span>
          </div>
          <button type="button" onclick="document.getElementById('createdInviteAlert').classList.add('hidden')" class="text-xs text-emerald-400/60 hover:text-emerald-400 font-mono">✕</button>
        </div>
        <p class="text-xs text-appTextMuted" data-i18n="inviteCopyHint">Bu bağlantı yalnızca bir kez gösterilir. Davet edilen kullanıcıya iletin:</p>
        <div class="flex items-center gap-2">
          <input type="text" id="createdInviteUrlInput" readonly class="flex-1 px-3 py-1.5 rounded-lg border border-appBorder bg-appBg text-appText font-mono text-xs select-all">
          <button type="button" onclick="copyInviteUrl()" id="copyInviteBtn" class="px-3 py-1.5 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition font-mono cursor-pointer" data-i18n="btnCopy">Kopyala</button>
        </div>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-appMuted/60 border-b border-appBorder text-appTextMuted uppercase font-mono text-[10px] tracking-wider">
            <tr>
              <th class="px-5 py-3.5" data-i18n="thEmail">E-posta</th>
              <th class="px-4 py-3.5" data-i18n="thStatus">Durum</th>
              <th class="px-4 py-3.5 font-mono" data-i18n="thExpires">Son Geçerlilik</th>
              <th class="px-4 py-3.5 font-mono" data-i18n="thCreated">Oluşturulma</th>
              <th class="px-5 py-3.5 text-right" data-i18n="thActions">İşlemler</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-appBorder">
            ${invitationRowsHtml}
          </tbody>
        </table>
      </div>
    </section>

    <!-- User Management Section -->
    <section class="border border-appBorder bg-appSurface rounded-2xl overflow-hidden shadow-xs">
      <div class="p-5 border-b border-appBorder flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-base font-bold text-appText tracking-tight" data-i18n="userMgmtTitle">Kullanıcı Yönetimi</h2>
          <p class="text-xs text-appTextMuted mt-0.5" data-i18n="userMgmtDesc">Kullanıcı hesapları, roller, yetkiler ve bağlı veri durumları.</p>
        </div>
        <span class="px-2.5 py-1 rounded-lg bg-appMuted text-appText font-mono text-xs font-semibold border border-appBorder">${users.length} <span data-i18n="userCountSuffix">Kullanıcı</span></span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-appMuted/60 border-b border-appBorder text-appTextMuted uppercase font-mono text-[10px] tracking-wider">
            <tr>
              <th class="px-5 py-3.5" data-i18n="thEmail">E-posta</th>
              <th class="px-4 py-3.5" data-i18n="thRole">Rol</th>
              <th class="px-4 py-3.5 text-center" data-i18n="thCredentials">Hesap Sayısı</th>
              <th class="px-4 py-3.5 text-center" data-i18n="thSessions">Aktif Oturum</th>
              <th class="px-4 py-3.5 font-mono" data-i18n="thRegistered">Kayıt Tarihi</th>
              <th class="px-5 py-3.5 text-right" data-i18n="thActions">İşlemler</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-appBorder">
            ${userRowsHtml}
          </tbody>
        </table>
      </div>
    </section>
  <!-- Modal: Create Invitation -->
  <div id="inviteModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
    <div class="w-full max-w-md border border-appBorder bg-appSurface rounded-2xl p-6 shadow-xl space-y-4">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-bold text-appText" data-i18n="modalInviteTitle">Yeni Kullanıcı Davet Et</h3>
        <button type="button" onclick="closeInviteModal()" class="text-appTextMuted hover:text-appText text-sm font-mono cursor-pointer">✕</button>
      </div>
      <p class="text-xs text-appTextMuted" data-i18n="modalInviteDesc">Davet edilecek kullanıcının e-posta adresini girin. 24 saat geçerli tek kullanımlık bir bağlantı oluşturulacaktır.</p>
      <form id="inviteForm" onsubmit="createInvitation(event)" class="space-y-4">
        <div>
          <label class="block text-xs font-medium text-appTextMuted mb-1.5 font-mono" data-i18n="labelInviteEmail">E-posta Adresi</label>
          <input type="email" id="inviteEmailInput" required placeholder="user@example.com" class="w-full px-3.5 py-2.5 rounded-xl border border-appBorder bg-appBg text-appText text-xs font-mono focus:border-appAccent focus:outline-hidden transition">
        </div>
        <div id="inviteModalError" class="hidden text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-lg p-2.5 font-mono"></div>
        <div class="flex items-center justify-end gap-2 pt-2">
          <button type="button" onclick="closeInviteModal()" class="px-4 py-2 rounded-xl text-xs font-semibold border border-appBorder text-appTextMuted hover:text-appText transition font-mono cursor-pointer" data-i18n="btnCancel">İptal</button>
          <button type="submit" id="inviteSubmitBtn" class="px-4 py-2 rounded-xl text-xs font-bold bg-appAccent text-black hover:bg-appAccentHover transition font-mono cursor-pointer flex items-center gap-2">
            <span id="inviteSubmitSpinner" class="hidden animate-spin w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full"></span>
            <span data-i18n="btnSendInvite">Davet Oluştur</span>
          </button>
        </div>
      </form>
    </div>
  </div>
  </main>

  <!-- Client-Side Scripts -->
  <script>
    const I18N = {
      tr: {
        flag: "🇹🇷",
        backToDashboard: "Panoya Dön",
        adminPageTitle: "Sistem Yönetim Merkezi",
        adminPageDesc: "Sistem geneli kullanıcı yönetimi, aktif oturumlar ve SQLite telemetrisi.",
        summaryUsers: "Toplam Kullanıcı",
        summaryCredentials: "Toplam Hesap",
        summarySnapshots: "Kota Geçmişi",
        summarySessions: "Aktif Oturum",
        summaryDbSize: "Veritabanı Boyutu",
        summaryPoller: "Daemon Poller",
        pollerRunning: "Çalışıyor",
        pollerStopped: "Durduruldu",
        providerDistTitle: "Sağlayıcı Hesap Dağılımı",
        providerDistDesc: "Sistem genelinde tüm kullanıcılar tarafından bağlanan hesap sayıları.",
        noProviders: "Henüz kayıtlı bir sağlayıcı hesabı yok.",
        userMgmtTitle: "Kullanıcı Yönetimi",
        userMgmtDesc: "Kullanıcı hesapları, roller, yetkiler ve bağlı veri durumları.",
        userCountSuffix: "Kullanıcı",
        thEmail: "E-posta",
        thRole: "Rol",
        thCredentials: "Hesap Sayısı",
        thSessions: "Aktif Oturum",
        thRegistered: "Kayıt Tarihi",
        thActions: "İşlemler",
        btnPromote: "Yönetici Yap",
        btnDemote: "Kullanıcı Yap",
        btnDelete: "Sil",
        logoutText: "Çıkış",
        regPolicyTitle: "Kayıt Politikası",
        regStatusOpen: "Açık",
        regStatusClosed: "Kapalı",
        regPolicyDescOpen: "Açık (Yeni kullanıcılar kayıt olabilir)",
        regPolicyDescClosed: "Kapalı (Yalnızca yöneticiler davet edebilir/mevcut kullanıcılar erişebilir)",
        btnDisableRegistration: "Kayıtları Kapat",
        btnEnableRegistration: "Kayıtları Aç",
        invitationMgmtTitle: "Davet Yönetimi",
        invitationCountSuffix: "Davet",
        invitationMgmtDesc: "Kullanıcı davet bağlantıları oluşturun, durumlarını izleyin veya iptal edin.",
        btnNewInvite: "Yeni Davet Oluştur",
        inviteCreatedSuccess: "Davet bağlantısı oluşturuldu!",
        inviteCopyHint: "Bu bağlantı yalnızca bir kez gösterilir. Davet edilen kullanıcıya iletin:",
        btnCopy: "Kopyala",
        noInvitations: "Henüz oluşturulmuş bir davet bulunmuyor.",
        thStatus: "Durum",
        thExpires: "Son Geçerlilik",
        thCreated: "Oluşturulma",
        statusAccepted: "Kabul Edildi",
        statusRevoked: "İptal Edildi",
        statusExpired: "Süresi Doldu",
        statusPending: "Bekliyor",
        btnRevoke: "İptal Et",
        modalInviteTitle: "Yeni Kullanıcı Davet Et",
        modalInviteDesc: "Davet edilecek kullanıcının e-posta adresini girin. 24 saat geçerli tek kullanımlık bir bağlantı oluşturulacaktır.",
        labelInviteEmail: "E-posta Adresi",
        btnCancel: "İptal",
        btnSendInvite: "Davet Oluştur",
      },
      en: {
        flag: "🇬🇧",
        backToDashboard: "Dashboard",
        adminPageTitle: "System Administration",
        adminPageDesc: "System-wide user management, active sessions, and SQLite telemetry.",
        summaryUsers: "Total Users",
        summaryCredentials: "Total Credentials",
        summarySnapshots: "Usage Snapshots",
        summarySessions: "Active Sessions",
        summaryDbSize: "Database Size",
        summaryPoller: "Daemon Poller",
        pollerRunning: "Running",
        pollerStopped: "Stopped",
        providerDistTitle: "Provider Distribution",
        providerDistDesc: "Total accounts connected across all users in the system.",
        noProviders: "No provider accounts registered yet.",
        userMgmtTitle: "User Management",
        userMgmtDesc: "User accounts, roles, permissions, and connected resource states.",
        userCountSuffix: "Users",
        thEmail: "Email",
        thRole: "Role",
        thCredentials: "Credentials",
        thSessions: "Sessions",
        thRegistered: "Registered Date",
        thActions: "Actions",
        btnPromote: "Promote to Admin",
        btnDemote: "Demote to User",
        btnDelete: "Delete",
        logoutText: "Sign Out",
        regPolicyTitle: "Registration Policy",
        regStatusOpen: "Open",
        regStatusClosed: "Closed",
        regPolicyDescOpen: "Open (New users can register)",
        regPolicyDescClosed: "Closed (Only administrators can invite / existing users can access)",
        btnDisableRegistration: "Disable Registration",
        btnEnableRegistration: "Enable Registration",
        invitationMgmtTitle: "Invitation Management",
        invitationCountSuffix: "Invitations",
        invitationMgmtDesc: "Create user invitation links, monitor their status, or revoke them.",
        btnNewInvite: "New Invitation",
        inviteCreatedSuccess: "Invitation link created!",
        inviteCopyHint: "This link is shown only once. Share it with the invited user:",
        btnCopy: "Copy",
        noInvitations: "No invitations created yet.",
        thStatus: "Status",
        thExpires: "Expires",
        thCreated: "Created",
        statusAccepted: "Accepted",
        statusRevoked: "Revoked",
        statusExpired: "Expired",
        statusPending: "Pending",
        btnRevoke: "Revoke",
        modalInviteTitle: "Invite New User",
        modalInviteDesc: "Enter the email address of the user to invite. A single-use link valid for 24 hours will be created.",
        labelInviteEmail: "Email Address",
        btnCancel: "Cancel",
        btnSendInvite: "Create Invitation",
      }
    };

    let currentLang = localStorage.getItem('usage_lang') || 'tr';
    let currentMode = localStorage.getItem('usage_mode') || 'dark';

    function t(key) {
      return (I18N[currentLang] && I18N[currentLang][key]) || (I18N['tr'][key]) || key;
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key) el.innerHTML = t(key);
      });
      const flagEl = document.getElementById('langFlag');
      if (flagEl && I18N[currentLang]) flagEl.innerText = I18N[currentLang].flag;
      const labelEl = document.getElementById('langLabel');
      if (labelEl) labelEl.innerText = currentLang.toUpperCase();
    }

    function toggleLang() {
      currentLang = currentLang === 'tr' ? 'en' : 'tr';
      localStorage.setItem('usage_lang', currentLang);
      applyI18n();
    }

    function applyLightDarkMode(mode) {
      currentMode = mode;
      localStorage.setItem('usage_mode', mode);
      const isDark = mode === 'dark';
      document.documentElement.classList.toggle('dark', isDark);
      document.documentElement.classList.toggle('light', !isDark);
      const icon = document.getElementById('lightDarkIcon');
      if (icon) icon.innerText = isDark ? '☀️' : '🌙';
    }

    function toggleLightDark() {
      applyLightDarkMode(currentMode === 'dark' ? 'light' : 'dark');
    }

    function updateRole(userId, newRole) {
      const confirmMsg = currentLang === 'tr'
        ? ('Bu kullanıcının rolünü "' + newRole + '" olarak değiştirmek istediğinizden emin misiniz?')
        : ('Are you sure you want to change user role to "' + newRole + '"?');
      if (!confirm(confirmMsg)) return;

      fetch('/api/admin/users/' + encodeURIComponent(userId) + '/role', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole })
      })
      .then(async r => {
        const data = await r.json();
        if (!r.ok || !data.success) {
          alert(data.error || (currentLang === 'tr' ? 'Rol güncellenemedi' : 'Failed to update role'));
        } else {
          window.location.reload();
        }
      })
      .catch(err => alert(String(err)));
    }

    function deleteUser(userId, email) {
      const confirmMsg = currentLang === 'tr'
        ? ('"' + email + '" kullanıcısını kalıcı olarak silmek istediğinizden emin misiniz?\\n\\nBu işlem geri alınamaz. Kullanıcıya ait tüm oturumlar, kayıtlı API hesapları ve kota geçmişi silinecektir.')
        : ('Are you sure you want to permanently delete user "' + email + '"?\\n\\nThis action cannot be undone and will delete all user credentials, snapshots, and sessions.');
      if (!confirm(confirmMsg)) return;

      fetch('/api/admin/users/' + encodeURIComponent(userId), {
        method: 'DELETE'
      })
      .then(async r => {
        const data = await r.json();
        if (!r.ok || !data.success) {
          alert(data.error || (currentLang === 'tr' ? 'Kullanıcı silinemedi' : 'Failed to delete user'));
        } else {
          window.location.reload();
        }
      })
      .catch(err => alert(String(err)));
    }
    function toggleRegistration(allow) {
      const confirmMsg = currentLang === 'tr'
        ? (allow ? 'Kullanıcı kayıtlarını açmak istediğinizden emin misiniz?' : 'Kullanıcı kayıtlarını kapatmak istediğinizden emin misiniz? Yeni kullanıcılar hesap oluşturamayacaktır.')
        : (allow ? 'Are you sure you want to enable new user registration?' : 'Are you sure you want to disable new user registration? New users will not be able to create accounts.');
      if (!confirm(confirmMsg)) return;

      const btn = document.getElementById('regToggleBtn');
      const spinner = document.getElementById('regToggleSpinner');
      if (btn) btn.disabled = true;
      if (spinner) spinner.classList.remove('hidden');

      fetch('/api/admin/settings/registration', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ allowRegistration: allow })
      })
      .then(async r => {
        const data = await r.json();
        if (!r.ok || !data.success) {
          alert(data.error || (currentLang === 'tr' ? 'Ayar güncellenemedi' : 'Failed to update setting'));
          if (btn) btn.disabled = false;
          if (spinner) spinner.classList.add('hidden');
        } else {
          window.location.reload();
        }
      })
      .catch(err => {
        alert(String(err));
        if (btn) btn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
      });
    }


    function openInviteModal() {
      document.getElementById('inviteModal').classList.remove('hidden');
      document.getElementById('inviteEmailInput').value = '';
      document.getElementById('inviteModalError').classList.add('hidden');
      document.getElementById('inviteEmailInput').focus();
    }

    function closeInviteModal() {
      document.getElementById('inviteModal').classList.add('hidden');
    }

    async function createInvitation(e) {
      e.preventDefault();
      const email = document.getElementById('inviteEmailInput').value.trim();
      const errorEl = document.getElementById('inviteModalError');
      const spinner = document.getElementById('inviteSubmitSpinner');
      const submitBtn = document.getElementById('inviteSubmitBtn');
      errorEl.classList.add('hidden');
      spinner.classList.remove('hidden');
      submitBtn.disabled = true;

      try {
        const res = await fetch('/api/admin/invitations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          errorEl.innerText = data.error || (currentLang === 'tr' ? 'Davet oluşturulamadı' : 'Failed to create invitation');
          errorEl.classList.remove('hidden');
          return;
        }

        closeInviteModal();
        const alertBox = document.getElementById('createdInviteAlert');
        const urlInput = document.getElementById('createdInviteUrlInput');
        urlInput.value = data.inviteUrl || (window.location.origin + '/invite/' + data.token);
        alertBox.classList.remove('hidden');
        alertBox.scrollIntoView({ behavior: 'smooth' });
      } catch (err) {
        errorEl.innerText = currentLang === 'tr' ? 'Bağlantı hatası' : 'Network error';
        errorEl.classList.remove('hidden');
      } finally {
        spinner.classList.add('hidden');
        submitBtn.disabled = false;
      }
    }

    function copyInviteUrl() {
      const input = document.getElementById('createdInviteUrlInput');
      input.select();
      navigator.clipboard.writeText(input.value).then(() => {
        const btn = document.getElementById('copyInviteBtn');
        const orig = btn.innerText;
        btn.innerText = currentLang === 'tr' ? 'Kopyalandı!' : 'Copied!';
        setTimeout(() => { btn.innerText = orig; }, 2000);
      });
    }

    function revokeInvitation(id, email) {
      const msg = currentLang === 'tr'
        ? ('"' + email + '" için oluşturulan daveti iptal etmek istediğinizden emin misiniz?')
        : ('Are you sure you want to revoke invitation for "' + email + '"?');
      if (!confirm(msg)) return;

      fetch('/api/admin/invitations/' + encodeURIComponent(id), {
        method: 'DELETE'
      })
      .then(async r => {
        const data = await r.json();
        if (!r.ok || !data.success) {
          alert(data.error || (currentLang === 'tr' ? 'Davet iptal edilemedi' : 'Failed to revoke invitation'));
        } else {
          window.location.reload();
        }
      })
      .catch(() => {
        alert(currentLang === 'tr' ? 'Bağlantı hatası' : 'Network error');
      });
    }

    function logoutUser() {
      fetch('/api/auth/logout', { method: 'POST' }).finally(() => {
        window.location.href = '/login';
      });
    }

    // Initialize
    applyLightDarkMode(currentMode);
    applyI18n();
  </script>
</body>
</html>`;
}
function sanitizeReportError(msg: string): string {
  if (!msg) return "";
  let clean = String(msg);
  clean = clean.replace(/ya29\.[a-zA-Z0-9_-]+/g, "[REDACTED_TOKEN]");
  clean = clean.replace(/sk-[a-zA-Z0-9_-]+/g, "[REDACTED_KEY]");
  clean = clean.replace(/gho_[a-zA-Z0-9_]+/g, "[REDACTED_TOKEN]");
  clean = clean.replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, "Bearer [REDACTED]");
  clean = clean.replace(/[a-f0-9]{32,64}/gi, "[REDACTED_HASH]");
  return clean;
}

function getReportErrorMessage(report: UsageReport): string {
  const err = report.error || "";
  if (!err) return "";
  const raw = sanitizeReportError(err);
  const lower = raw.toLowerCase();
  if (lower.includes("rate limit") || lower.includes("429")) return "İstek Hız Sınırı Aşıldı";
  if (lower.includes("subscription") || lower.includes("aboneli") || lower.includes("subscription_required")) return "Abonelik Gerekli veya Süresi Dolmuş";
  if (lower.includes("permission_denied") || lower.includes("permission denied") || lower.includes("403")) return "Bu Servis İçin Yetkiniz Yok";
  if (lower.includes("unauthorized") || lower.includes("401") || lower.includes("invalid_grant") || lower.includes("token expired") || lower.includes("auth")) return "Yetkilendirme Hatası / Token Geçersiz";
  if (lower.includes("fetch") || lower.includes("network") || lower.includes("econnrefused") || lower.includes("timeout")) return "Bağlantı Hatası";
  return "Sorgulama Hatası: " + raw.slice(0, 60);
}

function renderDashboardHtml(initialReports: (UsageReport & { createdAt?: number; accent?: string | null })[] = [], user?: User): string {
  let initialTotalBal = 0;
  let initialExhausted = 0;

  for (const r of initialReports) {
    for (const l of r.limits || []) {
      if (l.amount && l.amount.unit === "usd" && typeof l.amount.remaining === "number") {
        if (l.id.includes("balance") || l.id.includes("credits")) initialTotalBal += l.amount.remaining;
      }
      if (l.status === "exhausted") initialExhausted++;
    }
  }

  const initialCardsHtml = initialReports.length === 0
    ? `<div class="col-span-full py-24 text-center text-appTextMuted text-sm" data-i18n="noAccounts">Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.</div>`
    : initialReports.map(r => {
        const limitsHtml = (r.limits || []).map(l => {
          let valueHtml = "";
          let barHtml = "";

          if (l.amount.unit === "percent") {
            const used = l.amount.used || 0;
            const isCritical = used >= 90;
            const barColor = isCritical ? "bg-rose-500" : "account-card-bar-fill";
            valueHtml = `<span class="account-card-value font-bold text-sm">${used.toFixed(1)}%</span>`;
            barHtml = `<div class="w-full account-card-bar-track h-1.5 rounded-full overflow-hidden mt-2"><div class="${barColor} h-full transition-all duration-300" style="width: ${Math.min(100, used)}%"></div></div>`;
          } else if (l.amount.unit === "usd") {
            const rem = l.amount.remaining ?? 0;
            valueHtml = `<span class="account-card-value font-bold text-sm">$${rem.toFixed(2)}</span>`;
          } else if (l.amount.unit === "credits") {
            const rem = l.amount.remaining ?? 0;
            valueHtml = `<span class="account-card-badge font-semibold text-xs px-2.5 py-0.5 rounded-md">${rem} Hak Mevcut</span>`;
          }

          let countdownHtml = "";
          if (l.window && l.window.resetsAt) {
            const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
            const hours = Math.floor(diffMin / 60);
            const mins = diffMin % 60;
            const timeLabel = hours > 0 ? `${hours}sa ${mins}dk` : `${mins}dk`;
            countdownHtml = `<span class="text-xs text-appTextMuted flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-appTextMuted/70"></span>Sıfırlanma: ${timeLabel}</span>`;
          }

          const cleanNotes = (l.notes || []).filter(n => !String(n).toLowerCase().includes("model"));
          const notesHtml = cleanNotes.map(n => `<span class="text-xs text-appTextMuted block mt-0.5">${n}</span>`).join("");

          return `
            <div class="account-card-box border rounded-xl p-3.5 space-y-1.5">
              <div class="flex justify-between items-center">
                <span class="text-sm font-semibold text-appText tracking-tight">${l.label}</span>
                ${valueHtml}
              </div>
              ${barHtml}
              <div class="flex justify-between items-center pt-1">
                ${countdownHtml}
              </div>
              ${notesHtml}
            </div>
          `;
        }).join("");

        const metaObj = (r as unknown as { metadata?: Record<string, unknown> }).metadata;
        const metaEmail = metaObj?.["email"] || metaObj?.["login"] || metaObj?.["username"] || metaObj?.["accountId"] || metaObj?.["userId"];
        let cleanLabel = (r.accountLabel || "Default").replace(/^Google \((.*)\)$/, "$1");
        const provTitle = formatProviderTitle(r.provider);
        if ((!cleanLabel || cleanLabel.toLowerCase() === provTitle.toLowerCase() || cleanLabel.toLowerCase() === (r.provider || "").toLowerCase() || cleanLabel === "Default") && metaEmail) {
          cleanLabel = String(metaEmail);
        }
        const cardAccent = r.accent || "default";
        const planNote = (r.limits || []).flatMap(l => l.notes || []).find(n => String(n).toLowerCase().startsWith("plan:"));
        const rawPlan = (metaObj && typeof metaObj["planType"] === "string" ? metaObj["planType"] : undefined) || (planNote ? planNote.replace(/^Plan:\s*/i, "").trim() : "");
        const planName = rawPlan ? rawPlan.toUpperCase() : "";
        const planBadgeHtml = planName
          ? `<span class="px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider rounded-md bg-appAccentSoft text-appAccent border border-appAccent/30 shadow-xs">${planName}</span>`
          : "";

        const hasLimits = Array.isArray(r.limits) && r.limits.length > 0;
        const isStale = Boolean(
          r.stale ||
          r.health === "stale" ||
          r.source === "stale" ||
          (Boolean(r.error) && hasLimits)
        );
        const isFirstError = Boolean(
          (r.health === "error" || r.error) && !isStale && !hasLimits
        );
        const cardStatus = isStale ? "stale" : isFirstError ? "error" : "healthy";

        const successTimestamp = (isStale && r.lastGoodFetchedAt) ? r.lastGoodFetchedAt : r.fetchedAt;
        const timeStr = successTimestamp ? new Date(successTimestamp).toLocaleTimeString() : "";
        const updateText = isStale
          ? `Son başarılı güncelleme: ${escapeHtml(timeStr)}`
          : `Son Güncelleme: ${escapeHtml(timeStr)}`;

        const staleBadgeHtml = isStale
          ? `<span data-status="stale" class="account-card-stale-badge bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-medium px-1.5 py-0.5 rounded flex items-center gap-1 shrink-0" title="Önbelleğe alınmış kotalar gösteriliyor">
              <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
              <span data-i18n="staleBadge">Eski Veri</span>
            </span>`
          : "";

        const rawError = getReportErrorMessage(r);
        let statusNoticeHtml = "";
        if (isStale) {
          const errorDesc = rawError ? `<span class="text-[11px] text-amber-400/90 block truncate">${escapeHtml(rawError)}</span>` : "";
          statusNoticeHtml = `
            <div data-stale-notice="true" role="status" aria-live="polite" class="account-card-stale-notice bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs px-3 py-2 rounded-xl flex items-start gap-2.5">
              <svg class="w-4 h-4 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              <div class="flex-1 space-y-0.5 min-w-0">
                <div class="font-medium flex items-center justify-between gap-2 flex-wrap">
                  <span data-i18n="staleNotice">Önbelleğe alınmış kotalar gösteriliyor</span>
                  <span class="text-[11px] text-amber-400/80 font-normal">Son başarılı güncelleme: ${escapeHtml(timeStr)}</span>
                </div>
                ${errorDesc}
              </div>
            </div>
          `;
        } else if (isFirstError) {
          const displayErr = rawError || "Kullanım verisi henüz alınamadı";
          statusNoticeHtml = `
            <div data-status="error" class="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs px-3 py-2 rounded-xl flex items-center gap-2">
              <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span class="truncate">${escapeHtml(displayErr)}</span>
            </div>
          `;
        }

        return `
          <div data-card-id="${r.credentialId || r.provider}" data-status="${cardStatus}" data-accent="${cardAccent}" class="account-card border rounded-2xl p-5 space-y-4 transition-all shadow-sm">
            <div class="flex justify-between items-start">
              <div>
                <div class="flex items-center gap-2 flex-wrap">
                  <h2 class="account-card-title font-bold text-base tracking-tight">${provTitle}</h2>
                  ${planBadgeHtml}
                  <span class="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">${escapeHtml(cleanLabel)}</span>
                  ${staleBadgeHtml}
                </div>
                <span class="text-xs text-appTextMuted block mt-1.5" ${isStale ? 'data-i18n="lastSuccessfulUpdate"' : 'data-i18n="lastUpdate"'}>${updateText}</span>
              </div>
            </div>
            ${statusNoticeHtml}
            <div class="space-y-2.5">${limitsHtml}</div>
          </div>
        `;
      }).join("");

  const initialJson = JSON.stringify(initialReports).replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>useMeter — Multi-Provider Quota & Balance Hub</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            appBg: 'var(--color-bg)',
            appSurface: 'var(--color-surface)',
            appBorder: 'var(--color-border)',
            appMuted: 'var(--color-muted)',
            appAccent: 'var(--color-accent)',
            appAccentHover: 'var(--color-accent-hover)',
            appAccentSoft: 'var(--color-accent-soft)',
            appText: 'var(--color-text)',
            appTextMuted: 'var(--color-text-muted)'
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --color-bg: #090a0d;
      --color-surface: #111318;
      --color-border: #1f232b;
      --color-muted: #171a21;
      --color-text: #f4f4f6;
      --color-text-muted: #8e95a5;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-soft: rgba(255, 152, 73, 0.12);
    }
    html.light {
      --color-bg: #f8fafc;
      --color-surface: #ffffff;
      --color-border: #e2e8f0;
      --color-muted: #f1f5f9;
      --color-text: #0f172a;
      --color-text-muted: #64748b;
      --color-accent: #ea580c;
      --color-accent-hover: #c2410c;
      --color-accent-soft: rgba(234, 88, 12, 0.1);
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
      font-variant-numeric: tabular-nums;
    }
    .drag-over {
      outline: 2px dashed var(--color-accent) !important;
      outline-offset: 4px;
    }
    .account-card {
      --card-bg: var(--color-surface);
      --card-border: var(--color-border);
      --card-border-hover: #3f3f46;
      --card-title: var(--color-text);
      --card-value: var(--color-text);
      --card-accent-soft: rgba(255, 255, 255, 0.05);
      --card-bar-fill: #10b981;
      background: var(--card-bg) !important;
      border-color: var(--card-border) !important;
      transition: all 0.2s ease;
    }
    .account-card:hover {
      border-color: var(--card-border-hover) !important;
    }
    .account-card[data-accent="default"],
    .account-card[data-accent=""] {
      --card-bg: var(--color-surface);
      --card-border: var(--color-border);
      --card-border-hover: #3f3f46;
      --card-title: var(--color-text);
      --card-value: var(--color-text);
      --card-accent-soft: rgba(255, 255, 255, 0.05);
      --card-bar-fill: #10b981;
    }
    /* Dark mode accents (default) */
    .dark .account-card[data-accent="amber"],
    html:not(.light) .account-card[data-accent="amber"] {
      --card-bg: linear-gradient(180deg, rgba(245, 158, 11, 0.08) 0%, rgba(22, 17, 12, 0.96) 100%);
      --card-border: rgba(245, 158, 11, 0.35);
      --card-border-hover: rgba(245, 158, 11, 0.7);
      --card-title: #fbbf24;
      --card-value: #f59e0b;
      --card-accent-soft: rgba(245, 158, 11, 0.14);
      --card-bar-fill: #f59e0b;
    }
    .dark .account-card[data-accent="emerald"],
    html:not(.light) .account-card[data-accent="emerald"] {
      --card-bg: linear-gradient(180deg, rgba(16, 185, 129, 0.08) 0%, rgba(12, 24, 18, 0.96) 100%);
      --card-border: rgba(16, 185, 129, 0.35);
      --card-border-hover: rgba(16, 185, 129, 0.7);
      --card-title: #34d399;
      --card-value: #10b981;
      --card-accent-soft: rgba(16, 185, 129, 0.14);
      --card-bar-fill: #10b981;
    }
    .dark .account-card[data-accent="cyan"],
    html:not(.light) .account-card[data-accent="cyan"] {
      --card-bg: linear-gradient(180deg, rgba(6, 182, 212, 0.08) 0%, rgba(12, 22, 26, 0.96) 100%);
      --card-border: rgba(6, 182, 212, 0.35);
      --card-border-hover: rgba(6, 182, 212, 0.7);
      --card-title: #22d3ee;
      --card-value: #06b6d4;
      --card-accent-soft: rgba(6, 182, 212, 0.14);
      --card-bar-fill: #06b6d4;
    }
    .dark .account-card[data-accent="violet"],
    html:not(.light) .account-card[data-accent="violet"] {
      --card-bg: linear-gradient(180deg, rgba(168, 85, 247, 0.08) 0%, rgba(20, 14, 28, 0.96) 100%);
      --card-border: rgba(168, 85, 247, 0.35);
      --card-border-hover: rgba(168, 85, 247, 0.7);
      --card-title: #c084fc;
      --card-value: #a855f7;
      --card-accent-soft: rgba(168, 85, 247, 0.14);
      --card-bar-fill: #a855f7;
    }
    .dark .account-card[data-accent="slate"],
    html:not(.light) .account-card[data-accent="slate"] {
      --card-bg: linear-gradient(180deg, rgba(56, 189, 248, 0.08) 0%, rgba(14, 20, 28, 0.96) 100%);
      --card-border: rgba(56, 189, 248, 0.35);
      --card-border-hover: rgba(56, 189, 248, 0.7);
      --card-title: #7dd3fc;
      --card-value: #38bdf8;
      --card-accent-soft: rgba(56, 189, 248, 0.14);
      --card-bar-fill: #38bdf8;
    }

    /* Light mode accents */
    .light .account-card[data-accent="amber"] {
      --card-bg: linear-gradient(180deg, rgba(254, 243, 199, 0.5) 0%, #ffffff 100%);
      --card-border: rgba(245, 158, 11, 0.45);
      --card-border-hover: rgba(245, 158, 11, 0.8);
      --card-title: #b45309;
      --card-value: #d97706;
      --card-accent-soft: rgba(245, 158, 11, 0.15);
      --card-bar-fill: #d97706;
    }
    .light .account-card[data-accent="emerald"] {
      --card-bg: linear-gradient(180deg, rgba(209, 250, 229, 0.5) 0%, #ffffff 100%);
      --card-border: rgba(16, 185, 129, 0.45);
      --card-border-hover: rgba(16, 185, 129, 0.8);
      --card-title: #047857;
      --card-value: #059669;
      --card-accent-soft: rgba(16, 185, 129, 0.15);
      --card-bar-fill: #059669;
    }
    .light .account-card[data-accent="cyan"] {
      --card-bg: linear-gradient(180deg, rgba(207, 250, 254, 0.5) 0%, #ffffff 100%);
      --card-border: rgba(6, 182, 212, 0.45);
      --card-border-hover: rgba(6, 182, 212, 0.8);
      --card-title: #0e7490;
      --card-value: #0891b2;
      --card-accent-soft: rgba(6, 182, 212, 0.15);
      --card-bar-fill: #0891b2;
    }
    .light .account-card[data-accent="violet"] {
      --card-bg: linear-gradient(180deg, rgba(243, 232, 255, 0.5) 0%, #ffffff 100%);
      --card-border: rgba(168, 85, 247, 0.45);
      --card-border-hover: rgba(168, 85, 247, 0.8);
      --card-title: #7e22ce;
      --card-value: #9333ea;
      --card-accent-soft: rgba(168, 85, 247, 0.15);
      --card-bar-fill: #9333ea;
    }
    .light .account-card[data-accent="slate"] {
      --card-bg: linear-gradient(180deg, rgba(224, 242, 254, 0.5) 0%, #ffffff 100%);
      --card-border: rgba(56, 189, 248, 0.45);
      --card-border-hover: rgba(56, 189, 248, 0.8);
      --card-title: #0369a1;
      --card-value: #0284c7;
      --card-accent-soft: rgba(56, 189, 248, 0.15);
      --card-bar-fill: #0284c7;
    }

    .account-card-title {
      color: var(--card-title) !important;
    }
    .account-card-value {
      color: var(--card-value) !important;
    }
    .account-card-badge {
      background-color: var(--card-accent-soft) !important;
      border: 1px solid var(--card-border) !important;
      color: var(--card-title) !important;
    }
    .account-card-box {
      background: rgba(255, 255, 255, 0.02) !important;
      border-color: var(--color-border) !important;
      transition: all 0.2s ease;
    }
    .account-card[data-accent="amber"] .account-card-box {
      background: rgba(245, 158, 11, 0.05) !important;
      border-color: rgba(245, 158, 11, 0.2) !important;
    }
    .account-card[data-accent="emerald"] .account-card-box {
      background: rgba(16, 185, 129, 0.05) !important;
      border-color: rgba(16, 185, 129, 0.2) !important;
    }
    .account-card[data-accent="cyan"] .account-card-box {
      background: rgba(6, 182, 212, 0.05) !important;
      border-color: rgba(6, 182, 212, 0.2) !important;
    }
    .account-card[data-accent="violet"] .account-card-box {
      background: rgba(168, 85, 247, 0.05) !important;
      border-color: rgba(168, 85, 247, 0.2) !important;
    }
    .account-card[data-accent="slate"] .account-card-box {
      background: rgba(56, 189, 248, 0.05) !important;
      border-color: rgba(56, 189, 248, 0.2) !important;
    }

    .account-card-bar-track {
      background: rgba(255, 255, 255, 0.08) !important;
    }
    .light .account-card-bar-track {
      background: rgba(0, 0, 0, 0.08) !important;
    }
    .account-card-bar-fill {
      background-color: var(--card-bar-fill) !important;
    }
    .account-card-accent-badge {
      background-color: var(--card-accent-soft) !important;
      border: 1px solid var(--card-border) !important;
      color: var(--card-title) !important;
    }
    .account-card.is-edit-mode {
      border-style: dashed !important;
      border-color: var(--card-border-hover, var(--color-accent)) !important;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col transition-colors duration-200 text-sm overflow-x-hidden">
  <!-- Top Control Bar (Clean Engineering Wordmark, Zero Slop) -->
  <header class="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-4 sm:px-6 py-3 sticky top-0 z-20 transition-colors">
    <div class="max-w-screen-2xl mx-auto flex items-center justify-between gap-3">
      <!-- Minimalist Clean Logo & Plain-Language Sync Status -->
      <div class="flex items-center gap-2.5 sm:gap-3 shrink-0">
        <div class="flex items-center gap-2">
          <span class="font-extrabold tracking-wider text-appText text-lg font-mono">use<span class="text-appAccent">Meter</span></span>
          <span id="syncLiveDot" class="w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20" title="Last checked: just now" data-i18n-title="syncStatusJustNow"></span>
        </div>
        <div class="hidden sm:block h-4 w-px bg-appBorder"></div>
        <span id="headerSyncStatus" class="text-xs text-appTextMuted tracking-tight font-medium" data-i18n="syncStatusJustNow">Son kontrol: az önce</span>
        <span class="sr-only" data-i18n="title">useMeter</span>
      </div>

      <!-- Controls Right -->
      <div class="flex items-center gap-1.5 sm:gap-2 flex-wrap justify-end">
        <!-- Edit Mode Button -->
        <button onclick="toggleEditMode()" id="editModeBtn" title="Card Edit Mode" data-i18n-title="editModeTitle" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 20h9"></path>
            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
          </svg>
        </button>

        <!-- Grouping Dropdown -->
        <select id="groupSelect" onchange="changeGroup(this.value)" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition outline-none cursor-pointer">
          <option value="none" data-i18n="groupNone">Gruplama Yok</option>
          <option value="provider" data-i18n="groupProvider">Sağlayıcıya Göre</option>
        </select>

        <!-- Sorting Dropdown -->
        <select id="sortSelect" onchange="changeSort(this.value)" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition outline-none cursor-pointer">
          <option value="custom" data-i18n="sortCustom">Özel Sıralama</option>
          <option value="date_added" data-i18n="sortDateAdded">Eklenme Tarihi</option>
          <option value="highest_available" data-i18n="sortHighest">En Yüksek Kalan</option>
          <option value="lowest_available" data-i18n="sortLowest">En Düşük Kalan</option>
        </select>

        <!-- Settings Modal Trigger -->
        <button onclick="openSettingsModal()" id="settingsBtn" title="Settings" data-i18n-title="settingsTitle" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>

        <!-- Dark / Light Mode Toggle Button -->
        <button onclick="toggleLightDark()" id="lightDarkBtn" title="Dark / Light Mode" data-i18n-title="themeTitle" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <span id="lightDarkIcon">☀️</span>
        </button>

        <!-- Language Switcher Toggle with Flag -->
        <button onclick="toggleLang()" id="langBtn" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent/50 transition flex items-center gap-1.5 sm:gap-2">
          <span id="langFlag" class="text-base">🇹🇷</span>
          <span id="langLabel">TR</span>
        </button>

        <!-- Manual Poll Button -->
        <button onclick="pollNow()" id="pollBtn" class="h-9 px-3 sm:px-3.5 rounded-lg text-xs font-semibold bg-appMuted hover:bg-appBorder text-appText transition flex items-center gap-1.5 sm:gap-2 border border-appBorder">
          <svg id="pollSpinner" class="hidden animate-spin w-4 h-4 text-appAccent" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path>
          </svg>
          <span data-i18n="refresh">Yenile</span>
        </button>

        <!-- Connect Account Button -->
        <button onclick="openModal()" class="h-9 px-3.5 sm:px-4 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition flex items-center gap-1.5 shadow-sm">
          <span>+</span>
          <span data-i18n="addAccountText">Hesap Bağla</span>
        </button>

        ${user ? `
        <!-- User & Logout -->
        <div class="flex items-center gap-2 border-l border-appBorder pl-2 sm:pl-2.5">
          ${user.role === "admin" ? `
          <a href="/admin" id="adminPanelBtn" title="Yönetim Paneli" data-i18n-title="adminTitle" class="h-9 px-2.5 sm:px-3 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 transition flex items-center gap-1.5 text-xs font-semibold font-mono">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span data-i18n="adminLink">Admin</span>
          </a>` : ""}
          <span class="text-xs text-appTextMuted hidden md:inline-block max-w-[150px] truncate" title="${escapeHtml(user.email)}">${escapeHtml(user.email)}</span>
          <button type="button" onclick="logoutUser()" id="logoutBtn" title="Logout" data-i18n-title="logoutTitle" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-rose-400 hover:border-rose-500/50 transition flex items-center gap-1.5 text-xs font-semibold cursor-pointer">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
              <polyline points="16 17 21 12 16 7"></polyline>
              <line x1="21" y1="12" x2="9" y2="12"></line>
            </svg>
            <span data-i18n="logoutText">Çıkış</span>
          </button>
        </div>` : ""}
      </div>
    </div>
  </header>

  <!-- Summary Stats Strip -->
  <section class="border-b border-appBorder bg-appSurface/30 px-4 sm:px-6 py-3.5">
    <div class="max-w-screen-2xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs font-medium">
      <div class="flex items-center gap-4 sm:gap-6 flex-wrap">
        <div class="flex items-center gap-2">
          <span class="text-appTextMuted" data-i18n="summaryActive">Aktif Hesaplar:</span>
          <span id="statActiveCount" class="font-bold text-appText text-sm">${initialReports.length}</span>
        </div>
        <div class="flex items-center gap-2 border-l border-appBorder pl-4 sm:pl-6">
          <span class="text-appTextMuted" data-i18n="summaryBalance">Toplam Ön Ödemeli Bakiye:</span>
          <span id="statTotalBalance" class="font-bold text-emerald-500 text-sm">$${initialTotalBal.toFixed(2)}</span>
        </div>
        <div class="flex items-center gap-2 border-l border-appBorder pl-4 sm:pl-6">
          <span class="text-appTextMuted" data-i18n="summaryExhausted">Kilitli/Biten Kota:</span>
          <span id="statExhaustedCount" class="font-bold text-appText text-sm">${initialExhausted}</span>
        </div>
      </div>
      <div class="text-xs text-appTextMuted flex items-center gap-2">
        <span id="editModeNotice" class="hidden text-appAccent font-semibold animate-pulse" data-i18n="editModeActive">✏️ Düzenleme Modu Aktif</span>
        <span data-i18n="autoSync">Otomatik Yenileme:</span>
        <span class="text-appAccent font-semibold">10s</span>
      </div>
    </div>
  </section>

  <!-- Main Container -->
  <main class="flex-1 max-w-screen-2xl w-full mx-auto p-4 sm:p-6 space-y-6">
    <div id="cardsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
      ${initialCardsHtml}
    </div>
  </main>

  <!-- Settings Modal (Theme Accent Picker & Preferences) -->
  <div id="settingsModal" class="fixed inset-0 bg-black/60 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-appSurface border border-appBorder rounded-2xl max-w-md w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
      <div class="flex justify-between items-center pb-3 border-b border-appBorder">
        <h3 class="font-bold text-appText text-base" data-i18n="settingsTitle">Ayarlar</h3>
        <button onclick="closeSettingsModal()" title="Close" data-i18n-title="close" class="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-2.5" data-i18n="themeAccent">Vurgu Rengi</label>
          <div class="grid grid-cols-5 gap-2.5">
            <button onclick="changeTheme('amber')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_amber">
              <span class="w-6 h-6 rounded-full bg-[#ff9849]"></span>
              <span class="text-[11px] font-medium text-appText">Amber</span>
            </button>
            <button onclick="changeTheme('emerald')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_emerald">
              <span class="w-6 h-6 rounded-full bg-[#10b981]"></span>
              <span class="text-[11px] font-medium text-appText">Emerald</span>
            </button>
            <button onclick="changeTheme('cyan')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_cyan">
              <span class="w-6 h-6 rounded-full bg-[#06b6d4]"></span>
              <span class="text-[11px] font-medium text-appText">Cyan</span>
            </button>
            <button onclick="changeTheme('violet')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_violet">
              <span class="w-6 h-6 rounded-full bg-[#a855f7]"></span>
              <span class="text-[11px] font-medium text-appText">Violet</span>
            </button>
            <button onclick="changeTheme('slate')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_slate">
              <span class="w-6 h-6 rounded-full bg-[#38bdf8]"></span>
              <span class="text-[11px] font-medium text-appText">Slate</span>
            </button>
          </div>
        </div>
      </div>

      <div class="flex justify-end pt-3 border-t border-appBorder">
        <button onclick="closeSettingsModal()" class="px-4 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition" data-i18n="close">Kapat</button>
      </div>
    </div>
  </div>

  <!-- Add Credential / OAuth Modal -->
  <div id="modal" class="fixed inset-0 bg-black/60 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-appSurface border border-appBorder rounded-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
      <div class="flex justify-between items-center pb-3 border-b border-appBorder">
        <div>
          <h3 class="font-bold text-appText text-base" data-i18n="modalTitle">AI Hesabı Bağla</h3>
          <p class="text-xs text-appTextMuted mt-0.5" data-i18n="modalSubtitle">OAuth veya doğrudan API anahtarıyla kota takibi kurun.</p>
        </div>
        <button onclick="closeModal()" title="Close" data-i18n-title="close" class="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
      </div>

      <!-- Segmented Tab Switcher -->
      <div class="flex p-1 bg-appMuted rounded-xl border border-appBorder text-xs">
        <button onclick="switchTab('oauth')" id="tabOAuth" class="flex-1 py-2 font-semibold rounded-lg bg-appSurface text-appText shadow-sm transition" data-i18n="tabOAuth">
          OAuth ile Oturum Aç
        </button>
        <button onclick="switchTab('manual')" id="tabManual" class="flex-1 py-2 font-semibold rounded-lg text-appTextMuted hover:text-appText transition" data-i18n="tabManual">
          Manuel API Key
        </button>
      </div>

      <!-- OAuth Flow Options with Crisp Brand Marks -->
      <div id="oauthSection" class="space-y-3.5">
        <p class="text-xs text-appTextMuted leading-relaxed" data-i18n="oauthDesc">Resmi sağlayıcı girişine yönlendirilirsiniz. Token'lar yerel veritabanında AES-256-GCM ile şifrelenir.</p>

        <div id="oauthProvidersList" class="space-y-2 max-h-[48vh] overflow-y-auto pr-1">
          <!-- 1. Antigravity -->
          <button onclick="startGoogleOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" role="img"><path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"/><path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.34 24 12 24z"/><path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.17 0 9.99 0 12s.45 3.83 1.25 5.42l4.03-3.15z"/><path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="googleTitle">Antigravity (Google AI Pro)</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="googleDesc">Gemini ve Claude & GPT model havuzu kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 2. OpenAI Codex -->
          <button onclick="startCodexOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-emerald-400"><path d="M22.28 9.82a6 6 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9A6.06 6.06 0 0 0 4.98 4.18a5.98 5.98 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 6 6 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.52 2.9A5.98 5.98 0 0 0 13.26 24a6.06 6.06 0 0 0 5.77-4.2 6 6 0 0 0 4-2.9 6.06 6.06 0 0 0-.75-7.08zm-9.02 12.61a4.48 4.48 0 0 1-2.88-1.04l.14-.08 4.78-2.76a.8.8 0 0 0 .39-.68v-6.74l2.02 1.17a.07.07 0 0 1 .04.05v5.58a4.5 4.5 0 0 1-4.49 4.5zm-9.66-4.13a4.47 4.47 0 0 1-.54-3.01l.15.08 4.78 2.76a.77.77 0 0 0 .78 0l5.84-3.37v2.33a.08.08 0 0 1-.03.06l-4.84 2.8a4.5 4.5 0 0 1-6.14-1.65zM2.34 7.9a4.49 4.49 0 0 1 2.37-1.98V11.6a.77.77 0 0 0 .39.68l5.81 3.35-2.02 1.17a.08.08 0 0 1-.07 0l-4.83-2.79A4.5 4.5 0 0 1 2.34 7.9zm16.6 3.85L13.1 8.38l2.02-1.16a.08.08 0 0 1 .07 0l4.83 2.79a4.5 4.5 0 0 1 .68 4.79l-.14.08-4.78 2.76a.8.8 0 0 0-.39.68v6.74l-2.02-1.17a.07.07 0 0 1-.04-.05V19.5a4.5 4.5 0 0 1 4.49-4.5z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="codexTitle">OpenAI ChatGPT / Codex</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="codexDesc">Plus / Pro 5 saatlik ve haftalık kotalar</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 3. Anthropic Claude -->
          <button onclick="startClaudeOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-amber-500"><path d="M13.2 2h-2.4v7.3L5.64 4.14 3.94 5.84l5.16 5.16H2v2.4h7.1l-5.16 5.16 1.7 1.7 5.16-5.16V22h2.4v-7.1l5.16 5.16 1.7-1.7-5.16-5.16H22v-2.4h-7.3l5.16-5.16-1.7-1.7-5.16 5.16V2z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="claudeTitle">Anthropic Claude Pro/Max</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="claudeDesc">5h oturum ve haftalık Opus/Sonnet kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 4. GitHub Copilot -->
          <button onclick="startCopilotOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-purple-400"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="copilotTitle">GitHub Copilot</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="copilotDesc">Completions ve Chat kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 5. Cursor (Pro/Ultra) -->
          <button onclick="startCursorOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-cyan-400"><path d="M4 2l16 10-7.5 2-4.5 8L4 2z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="cursorTitle">Cursor (Pro/Ultra)</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="cursorDesc">Hızlı istekler ve on-demand kullanım</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 6. xAI Grok -->
          <button onclick="startXaiOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-slate-100"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="xaiTitle">xAI Grok</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="xaiDesc">Grok-2/3 model kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 7. Kimi Code (Moonshot) -->
          <button onclick="startKimiOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-indigo-400"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14.5v-3.2l3.4 3.2h2.6l-4.5-4.2 4.2-4.8h-2.5l-3.2 3.7V7.5H11v9h2z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="kimiTitle">Kimi Code (Moonshot)</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="kimiDesc">Kimi K1.5 ve context kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>
          <!-- 8. OpenRouter -->
          <button onclick="startOpenRouterOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" class="text-teal-400"><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 6.5l8 3M9 14.5l8 3M6.5 7v10M17.5 7v10"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="openrouterTitle">OpenRouter</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="openrouterDesc">Otomatik PKCE ile API anahtarı ve bakiye</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- 9. Devin AI -->
          <button onclick="startDevinOAuth()" class="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" class="text-emerald-300"><path d="M4 4h7v7H4V4zm9 0h7v7h-7V4zm-9 9h7v7H4v-7zm9 0h7v7h-7v-7z"/></svg>
              </div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="devinTitle">Devin AI</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="devinDesc">Cognition Devin kota ve oturum takibi</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent shrink-0" data-i18n="loginBtn">Oturum Aç →</span>
          </button>
        </div>

        <!-- Unified Device Code Active State Panel -->
        <div id="deviceAuthPanel" class="hidden p-4 rounded-xl bg-appMuted border border-appAccent/40 space-y-3.5">
          <div class="flex items-center justify-between">
            <span id="deviceWaitText" class="text-xs font-semibold text-appText" data-i18n="deviceWaitGeneric">Yetkilendirme Bekleniyor:</span>
            <span id="deviceProviderBadge" class="text-xs px-2.5 py-0.5 rounded-full bg-appAccentSoft text-appAccent font-semibold tracking-wide">OAuth</span>
          </div>
          <div class="flex items-center gap-2 bg-appSurface border border-appBorder rounded-lg p-2.5">
            <code id="deviceUserCode" class="flex-1 font-mono text-base font-bold tracking-widest text-center text-appAccent select-all">...</code>
            <button type="button" onclick="copyDeviceCode()" id="copyCodeBtn" class="px-3 py-1.5 text-xs font-semibold rounded-md bg-appMuted hover:bg-appBorder text-appText transition flex items-center gap-1.5" data-i18n="copyCode">
              <span>📋</span>
              <span id="copyBtnText">Kopyala</span>
            </button>
          </div>
          <p id="deviceDescText" class="text-xs text-appTextMuted leading-relaxed" data-i18n="deviceDescGeneric">
            Açılan doğrulama sayfasına bu kodu girin. Onaylandığı an panel otomatik olarak güncellenecektir.
          </p>
          <div class="flex items-center justify-between pt-1">
            <a id="deviceAuthLink" href="#" target="_blank" class="inline-flex items-center gap-1 text-xs font-semibold text-appAccent hover:underline" data-i18n="reopenLink">
              Onay Sayfasını Yeniden Aç ↗
            </a>
            <button type="button" onclick="cancelDeviceAuth()" class="text-xs text-appTextMuted hover:text-appText transition font-medium" data-i18n="cancel">İptal</button>
          </div>
        </div>

        <!-- Unified Browser OAuth Active State Panel -->
        <div id="browserAuthPanel" class="hidden p-4 rounded-xl bg-appMuted border border-appAccent/40 space-y-3">
          <div class="flex items-center gap-3">
            <div class="w-4 h-4 border-2 border-appAccent border-t-transparent rounded-full animate-spin shrink-0"></div>
            <span class="text-xs font-semibold text-appText" id="browserAuthText">Tarayıcıda onay bekleniyor...</span>
          </div>
          <p class="text-xs text-appTextMuted leading-relaxed">Açılan sekmede yetkilendirmeyi tamamlayın. Onaylandığında otomatik olarak kapanacaktır.</p>
          <div class="flex items-center justify-between pt-1">
            <a id="browserAuthLink" href="#" target="_blank" class="text-xs font-semibold text-appAccent hover:underline" data-i18n="reopenLink">Sayfayı Yeniden Aç ↗</a>
            <button type="button" onclick="cancelBrowserAuth()" class="text-xs text-appTextMuted hover:text-appText transition font-medium" data-i18n="cancel">İptal</button>
          </div>
        </div>
      </div>

      <!-- Manual API Key Form Section -->
      <form id="manualSection" onsubmit="handleManualSave(event)" class="hidden space-y-4">
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="provider">Sağlayıcı</label>
          <select id="providerSelect" onchange="updateSecretHelp(this.value)" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none cursor-pointer">
            <option value="antigravity">Antigravity (Google AI Pro)</option>
            <option value="openai-codex">OpenAI ChatGPT / Codex</option>
            <option value="github-copilot">GitHub Copilot</option>
            <option value="cursor">Cursor</option>
            <option value="anthropic">Anthropic Claude</option>
            <option value="openrouter">OpenRouter</option>
            <option value="deepseek">DeepSeek</option>
            <option value="xai-oauth">xAI Grok</option>
            <option value="zai">Zhipu AI (GLM)</option>
            <option value="minimax-code">MiniMax Code</option>
            <option value="cline-pass">Cline Pass</option>
            <option value="devin">Devin</option>
            <option value="umans">Umans</option>
            <option value="google-gemini-cli">Gemini CLI</option>
            <option value="kimi-code">Kimi Code</option>
            <option value="opencode-go">OpenCode Go</option>
            <option value="alibaba-token-plan">Alibaba Qwen</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="accountLabel">Hesap Adı / Etiket</label>
          <input type="text" id="accountLabel" placeholder="Örn: Kişisel Pro, İş Hesabı" data-i18n-placeholder="accountLabelPlaceholder" required class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="accountAccent">Kart Vurgu Rengi</label>
          <select id="accountAccentSelect" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none cursor-pointer">
            <option value="" data-i18n="accentDefault">Varsayılan (Tema Rengi)</option>
            <option value="amber">Amber</option>
            <option value="emerald">Emerald</option>
            <option value="cyan">Cyan</option>
            <option value="violet">Violet</option>
            <option value="slate">Slate</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="credentialType">Kimlik Türü</label>
          <select id="credentialType" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none">
            <option value="api_key" data-i18n="apiKey">API Anahtarı</option>
            <option value="oauth" data-i18n="oauthToken">OAuth Access Token</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="secretLabel">Secret / Token</label>
          <input type="password" id="secretValue" placeholder="Bearer token veya API anahtarı" required class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
          <p id="secretHelpText" class="text-[11px] text-appTextMuted mt-1">Google OAuth Access Token veya Refresh Token</p>
        </div>
        <div class="flex justify-end gap-2.5 pt-3 border-t border-appBorder">
          <button type="button" onclick="closeModal()" class="px-4 py-2 rounded-lg text-xs font-semibold bg-appMuted hover:bg-appBorder text-appText transition" data-i18n="cancel">İptal</button>
          <button type="submit" class="px-5 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition whitespace-nowrap" data-i18n="saveAndPoll">Kaydet ve Sorgula</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Client Script -->
  <script>
    const THEME_ACCENTS = {
      amber: { accent: '#ff9849', accentHover: '#ea7c2b', accentSoft: 'rgba(255, 152, 73, 0.12)' },
      emerald: { accent: '#10b981', accentHover: '#059669', accentSoft: 'rgba(16, 185, 129, 0.12)' },
      cyan: { accent: '#06b6d4', accentHover: '#0891b2', accentSoft: 'rgba(6, 182, 212, 0.12)' },
      violet: { accent: '#a855f7', accentHover: '#9333ea', accentSoft: 'rgba(168, 85, 247, 0.12)' },
      slate: { accent: '#38bdf8', accentHover: '#0284c7', accentSoft: 'rgba(56, 189, 248, 0.12)' }
    };

    const I18N = {
      tr: {
        flag: "🇹🇷",
        title: "useMeter",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Yenile",
        addAccountText: "Hesap Bağla",
        summaryActive: "Aktif Hesaplar:",
        summaryBalance: "Toplam Ön Ödemeli Bakiye:",
        summaryExhausted: "Kilitli/Biten Kota:",
        autoSync: "Otomatik Yenileme:",
        editModeActive: "✏️ Düzenleme Modu Aktif",
        editModeTitle: "Kart Düzenleme Modu",
        settingsTitle: "Ayarlar",
        themeTitle: "Koyu / Aydınlık Mod",
        deleteAccount: "Hesabı Kaldır",
        editLabel: "Etiketi Düzenle",
        save: "Kaydet",
        saveAndPoll: "Kaydet ve Sorgula",
        cancel: "İptal",
        noAccounts: "Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.",
        lastUpdate: "Son Güncelleme",
        deleteConfirm: "Bu hesabı kaldırmak istediğinizden emin misiniz?",
        resetsIn: "Sıfırlanma",
        rightsAvailable: "Hak Mevcut",
        modalTitle: "AI Hesabı Bağla",
        modalSubtitle: "OAuth veya doğrudan API anahtarıyla kota takibi kurun.",
        tabOAuth: "OAuth ile Oturum Aç",
        tabManual: "Manuel API Key",
        oauthDesc: "Resmi sağlayıcı girişine yönlendirilirsiniz. Token'lar yerel veritabanında AES-256-GCM ile şifrelenir.",
        googleTitle: "Antigravity (Google AI Pro)",
        googleDesc: "Gemini ve Claude & GPT model havuzu kotaları",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5 saatlik ve haftalık kotalar",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h oturum ve haftalık Opus/Sonnet kotaları",
        loginBtn: "Oturum Aç →",
        deviceWait: "OpenAI Onayı Bekleniyor:",
        deviceDesc: "Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.",
        reopenLink: "Onay Sayfasını Yeniden Aç ↗",
        copilotTitle: "GitHub Copilot",
        copilotDesc: "Completions ve Chat kotaları",
        cursorTitle: "Cursor (Pro/Ultra)",
        cursorDesc: "Hızlı istekler ve on-demand kullanım",
        xaiTitle: "xAI Grok",
        xaiDesc: "Grok-2/3 model kotaları",
        kimiTitle: "Kimi Code (Moonshot)",
        kimiDesc: "Kimi K1.5 ve context kotaları",
        geminiCliTitle: "Google Gemini CLI",
        geminiCliDesc: "Code Assist & Gemini 2.5/3 Pro kotaları",
        openrouterTitle: "OpenRouter",
        openrouterDesc: "Otomatik PKCE ile API anahtarı ve bakiye",
        zaiTitle: "Zhipu AI (GLM / BigModel)",
        zaiDesc: "GLM-4 model kredileri ve bakiyesi",
        devinTitle: "Devin AI",
        devinDesc: "Cognition Devin kota ve oturum takibi",
        copyCode: "Kodu Kopyala",
        codeCopied: "Kopyalandı!",
        deviceWaitGeneric: "Yetkilendirme Bekleniyor:",
        deviceDescGeneric: "Açılan doğrulama sayfasına bu kodu girin. Onaylandığı an panel otomatik olarak güncellenecektir.",
        provider: "Sağlayıcı",
        accountLabel: "Hesap Adı / Etiket",
        accountLabelPlaceholder: "Örn: Kişisel Pro, İş Hesabı",
        accountAccent: "Kart Vurgu Rengi",
        cardAccent: "Kart Vurgusu",
        accentDefault: "Varsayılan (Tema Rengi)",
        credentialType: "Kimlik Türü",
        apiKey: "API Anahtarı",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        themeAccent: "Vurgu Rengi",
        close: "Kapat",
        groupSelect: "Gruplama",
        groupNone: "Gruplama Yok",
        groupProvider: "Sağlayıcıya Göre",
        editDisabledGrouped: "Gruplama etkinken düzenleme modu kullanılamaz",
        sortCustom: "Özel Sıralama",
        sortDateAdded: "Eklenme Tarihi",
        sortHighest: "En Yüksek Kalan",
        sortLowest: "En Düşük Kalan",
        syncStatusJustNow: "Son kontrol: az önce",
        syncStatusSec: "Son kontrol: {n} sn önce",
        syncStatusMin: "Son kontrol: {n} dk önce",
        pollingError: "Sorgulama Hatası",
        subscriptionError: "Abonelik Gerekli veya Süresi Dolmuş",
        permissionError: "Bu Servis İçin Yetkiniz Yok",
        rateLimitError: "İstek Hız Sınırı Aşıldı",
        networkError: "Bağlantı Hatası",
        authError: "Yetkilendirme Hatası / Token Geçersiz",
        statusStale: "Eski Veri",
        staleBadge: "Eski Veri",
        staleNotice: "Önbelleğe alınmış kotalar gösteriliyor",
        lastSuccessfulUpdate: "Son başarılı güncelleme:",
        initialUnavailable: "Kullanım verisi henüz alınamadı",
        logoutText: "Çıkış",
        logoutTitle: "Oturumu Kapat",
        adminLink: "Yönetim",
        adminTitle: "Yönetim Paneli"
      },
      en: {
        flag: "🇬🇧",
        title: "useMeter",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Refresh",
        addAccountText: "Add Account",
        summaryActive: "Active Accounts:",
        summaryBalance: "Total Prepaid Balance:",
        summaryExhausted: "Exhausted Quotas:",
        autoSync: "Auto-refresh:",
        editModeActive: "✏️ Edit Mode Active",
        save: "Save",
        saveAndPoll: "Save & Poll",
        cancel: "Cancel",
        themeTitle: "Dark / Light Mode",
        deleteAccount: "Remove Account",
        editLabel: "Edit Label",
        save: "Save",
        cancel: "Cancel",
        noAccounts: "No AI accounts connected yet. Click <b>+ Connect Account</b> to add one.",
        lastUpdate: "Updated",
        deleteConfirm: "Are you sure you want to remove this account?",
        resetsIn: "Resets in",
        rightsAvailable: "Available",
        modalTitle: "Connect AI Account",
        modalSubtitle: "Track quotas and credits via OAuth or direct API key.",
        tabOAuth: "Login with OAuth",
        tabManual: "Manual API Key",
        oauthDesc: "Redirect to official authorization. Tokens are encrypted locally via AES-256-GCM.",
        googleTitle: "Antigravity (Google AI Pro)",
        googleDesc: "Gemini and Claude & GPT shared quota pools",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5-hour rolling & weekly quotas",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h session and weekly Opus/Sonnet quotas",
        loginBtn: "Login →",
        deviceWait: "Waiting for OpenAI Approval:",
        deviceDesc: "Enter the code on the OpenAI confirmation page. The dashboard will automatically update.",
        reopenLink: "Re-open Authorization Page ↗",
        copilotTitle: "GitHub Copilot",
        copilotDesc: "Completions & Chat quotas",
        cursorTitle: "Cursor (Pro/Ultra)",
        cursorDesc: "Fast requests & on-demand usage",
        xaiTitle: "xAI Grok",
        xaiDesc: "Grok-2/3 model quotas",
        kimiTitle: "Kimi Code (Moonshot)",
        kimiDesc: "Kimi K1.5 & context quotas",
        geminiCliTitle: "Google Gemini CLI",
        geminiCliDesc: "Code Assist & Gemini 2.5/3 Pro quotas",
        openrouterTitle: "OpenRouter",
        openrouterDesc: "Automatic PKCE key exchange & balance",
        zaiTitle: "Zhipu AI (GLM / BigModel)",
        zaiDesc: "GLM-4 model credits & balance",
        devinTitle: "Devin AI",
        devinDesc: "Cognition Devin quota & session tracking",
        copyCode: "Copy Code",
        codeCopied: "Copied!",
        deviceWaitGeneric: "Authorization Pending:",
        deviceDescGeneric: "Enter this code on the verification page. The dashboard will update automatically.",
        provider: "Provider",
        accountLabel: "Account Label",
        accountLabelPlaceholder: "e.g. Personal Pro, Work Key",
        accountAccent: "Card Accent Color",
        cardAccent: "Card Accent",
        accentDefault: "Default (Theme Color)",
        credentialType: "Credential Type",
        apiKey: "API Key",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        themeAccent: "Accent Color",
        close: "Close",
        groupSelect: "Grouping",
        groupNone: "No Grouping",
        groupProvider: "By Provider",
        editDisabledGrouped: "Edit mode is disabled while grouped",
        sortCustom: "Custom Order",
        sortDateAdded: "Date Added",
        sortHighest: "Highest Available",
        sortLowest: "Lowest Available",
        syncStatusJustNow: "Last checked: just now",
        syncStatusSec: "Last checked: {n}s ago",
        syncStatusMin: "Last checked: {n}m ago",
        pollingError: "Polling Error",
        subscriptionError: "Subscription Required or Inactive",
        permissionError: "Permission Denied for This Service",
        rateLimitError: "Rate Limit Exceeded",
        networkError: "Connection Error",
        authError: "Authentication Error / Invalid Token",
        statusStale: "Stale",
        staleBadge: "Stale",
        staleNotice: "Showing cached limits",
        lastSuccessfulUpdate: "Last successful update:",
        initialUnavailable: "Usage data not yet available",
        logoutText: "Sign Out",
        logoutTitle: "Sign out",
        adminLink: "Admin",
        adminTitle: "Admin Panel"
      }
    };

    function detectInitialLang() {
      const saved = localStorage.getItem('usage_lang');
      if (saved === 'tr' || saved === 'en') return saved;
      const browserLang = (navigator.language || navigator.userLanguage || '').toLowerCase();
      return browserLang.startsWith('tr') ? 'tr' : 'en';
    }

    let currentLang = detectInitialLang();
    let currentMode = localStorage.getItem('usage_mode') || 'dark';
    let currentAccent = localStorage.getItem('usage_accent') || 'amber';
    let currentSort = localStorage.getItem('usage_sort') || 'custom';
    let currentGroup = localStorage.getItem('usage_group') || 'none';
    let isEditMode = false;
    let editingCardId = null;
    let draggedCardId = null;
    let cachedReports = ${initialJson};
    let lastPolledAt = Date.now();

    function t(key) {
      return (I18N[currentLang] && I18N[currentLang][key]) || (I18N['tr'][key]) || key;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
    async function logoutUser() {
      try {
        await fetch('/api/auth/logout', { method: 'POST' });
      } catch {}
      window.location.href = '/login';
    }


    function formatProviderTitle(provider) {
      const p = (provider || '').toLowerCase();
      if (p === 'antigravity' || p === 'google-antigravity' || p === 'google') return 'Antigravity';
      if (p === 'openai-codex' || p === 'codex') return 'OpenAI Codex';
      if (p === 'openrouter') return 'OpenRouter';
      if (p === 'deepseek') return 'DeepSeek';
      if (p === 'anthropic' || p === 'claude') return 'Anthropic Claude';
      if (p === 'cursor') return 'Cursor';
      if (p === 'github-copilot' || p === 'copilot') return 'GitHub Copilot';
      if (p === 'xai-oauth' || p === 'grok' || p === 'xai') return 'xAI Grok';
      if (p === 'zai' || p === 'zhipu' || p === 'glm') return 'Zhipu AI (GLM)';
      if (p === 'minimax-code' || p === 'minimax') return 'MiniMax Code';
      if (p === 'cline-pass' || p === 'clinepass') return 'Cline Pass';
      if (p === 'devin') return 'Devin';
      if (p === 'umans') return 'Umans';
      if (p === 'google-gemini-cli' || p === 'gemini-cli') return 'Gemini CLI';
      if (p === 'kimi-code' || p === 'kimi' || p === 'moonshot') return 'Kimi Code';
      if (p === 'opencode-go') return 'OpenCode Go';
      if (p === 'alibaba-token-plan') return 'Alibaba Qwen';
      return provider.charAt(0).toUpperCase() + provider.slice(1);
    }

    function sanitizeErrorMessage(msg) {
      if (!msg) return '';
      let clean = String(msg);
      clean = clean.replace(/ya29\.[a-zA-Z0-9_-]+/g, '[REDACTED_TOKEN]');
      clean = clean.replace(/sk-[a-zA-Z0-9_-]+/g, '[REDACTED_KEY]');
      clean = clean.replace(/gho_[a-zA-Z0-9_]+/g, '[REDACTED_TOKEN]');
      clean = clean.replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED]');
      clean = clean.replace(/[a-f0-9]{32,64}/gi, '[REDACTED_HASH]');
      return clean;
    }

    function translateErrorText(text) {
      return String(text)
        .replaceAll('aboneliği aktif değil veya süresi dolmuş', 'subscription is inactive or expired')
        .replaceAll('abonelik aktif değil veya süresi dolmuş', 'subscription is inactive or expired')
        .replaceAll('aboneliği aktif değil', 'subscription is inactive')
        .replaceAll('süresi dolmuş', 'expired')
        .replaceAll('abonelik gerekli', 'subscription required')
        .replaceAll('abonelik', 'subscription')
        .replaceAll('yetkili değil', 'unauthorized')
        .replaceAll('yetkisiz', 'unauthorized')
        .replaceAll('geçersiz', 'invalid')
        .replaceAll('hata', 'error')
        .replaceAll('sorgulama', 'query');
    }

    function getLocalizedReportError(report) {
      const err = report.error || (report.status === 'error' ? (report.statusMessage || report.message || 'Error') : null);
      if (!err) return null;
      const raw = sanitizeErrorMessage(err);
      const lower = raw.toLowerCase();
      if (lower.includes('rate limit') || lower.includes('429')) {
        return t('rateLimitError');
      }
      if (lower.includes('subscription') || lower.includes('aboneli') || lower.includes('subscription_required')) {
        return t('subscriptionError');
      }
      if (lower.includes('permission_denied') || lower.includes('permission denied') || lower.includes('403')) {
        return t('permissionError');
      }
      if (lower.includes('unauthorized') || lower.includes('401') || lower.includes('invalid_grant') || lower.includes('token expired') || lower.includes('auth')) {
        return t('authError');
      }
      if (lower.includes('fetch') || lower.includes('network') || lower.includes('econnrefused') || lower.includes('timeout')) {
        return t('networkError');
      }
      return t('pollingError') + ': ' + translateErrorText(raw).slice(0, 60);
    }

    function translateLimitLabel(label, id) {
      const str = String(label || id || '');
      if (currentLang === 'tr') {
        const trMap = {
          'fast_requests': 'Cursor Hızlı İstek Kotası',
          'gemini_5h': 'Gemini: 5 Saatlik Limit',
          'gemini_weekly': 'Gemini: Haftalık Limit',
          'claude_gpt_5h': 'Claude & GPT: 5 Saatlik Limit',
          'claude_gpt_weekly': 'Claude & GPT: Haftalık Limit',
          'primary_window': '5 Saatlik Kayan Kota',
          'primary': '5 Saatlik Kayan Kota',
          'secondary_window': 'Haftalık / Uzun Dönem Kotası',
          'secondary': 'Haftalık / Uzun Dönem Kotası',
          'reset_credits': 'Kota Sıfırlama Hakkı (Usage Reset)',
          'premium_interactions': 'Premium İstekler (Claude 3.7 / o3-mini)',
          'chat_quota': 'Copilot Chat Kotası',
          'grok_credits': 'xAI Grok Kullanım Kotası',
          'account_balance': 'Hesap Net Bakiyesi',
          'total_credits': 'Hesap Net Bakiyesi',
          'key_usage': 'API Anahtar Harcaması',
          'rate_limit': 'İstek Hız Sınırı',
          'balance_usd': 'Kullanılabilir Bakiye (USD)',
          '5h': '5 Saatlik Kayan Kota',
          '7d': 'Haftalık Genel Kota'
        };
        return trMap[id] || str;
      }

      const enMap = {
        'fast_requests': 'Cursor Fast Requests Quota',
        'gemini_5h': 'Gemini: 5-Hour Limit',
        'gemini_weekly': 'Gemini: Weekly Limit',
        'claude_gpt_5h': 'Claude & GPT: 5-Hour Limit',
        'claude_gpt_weekly': 'Claude & GPT: Weekly Limit',
        'primary_window': '5-Hour Rolling Quota',
        'primary': '5-Hour Rolling Quota',
        'secondary_window': 'Weekly / Long-Term Quota',
        'secondary': 'Weekly / Long-Term Quota',
        'reset_credits': 'Usage Reset Allowance',
        'premium_interactions': 'Premium Requests (Claude 3.7 / o3-mini)',
        'chat_quota': 'Copilot Chat Quota',
        'grok_credits': 'xAI Grok Usage Quota',
        'account_balance': 'Account Net Balance',
        'total_credits': 'Account Net Balance',
        'key_usage': 'API Key Spending',
        'rate_limit': 'Rate Limit',
        'balance_usd': 'Available Balance (USD)',
        '5h': '5-Hour Rolling Quota',
        '7d': 'Weekly Quota'
      };
      if (enMap[id]) return enMap[id];

      return str
        .replaceAll('Cursor Hızlı İstek Kotası (Fast Requests)', 'Cursor Fast Requests Quota')
        .replaceAll('Cursor Hızlı İstek Kotası', 'Cursor Fast Requests Quota')
        .replaceAll('5 Saatlik Kayan Kota', '5-Hour Rolling Quota')
        .replaceAll('5 Saatlik Limit', '5-Hour Limit')
        .replaceAll('Haftalık / Uzun Dönem Kotası', 'Weekly / Long-Term Quota')
        .replaceAll('Haftalık / Uzun Dönem Penceresi', 'Weekly / Long-Term Window')
        .replaceAll('Haftalık Genel Kota', 'Weekly Quota')
        .replaceAll('Haftalık Kota', 'Weekly Quota')
        .replaceAll('Haftalık Limit', 'Weekly Limit')
        .replaceAll('Haftalık Pencere', 'Weekly Window')
        .replaceAll('Haftalık', 'Weekly')
        .replaceAll('5 Saatlik Kayan Pencere', '5-Hour Rolling Window')
        .replaceAll('Kayan Kota', 'Rolling Quota')
        .replaceAll('Kota Sıfırlama Hakkı (Usage Reset)', 'Usage Reset Allowance')
        .replaceAll('Kota Sıfırlama Hakkı', 'Usage Reset Allowance')
        .replaceAll('Hesap Net Bakiyesi', 'Account Net Balance')
        .replaceAll('Kullanılabilir Bakiye', 'Available Balance')
        .replaceAll('İstek Hız Sınırı', 'Rate Limit')
        .replaceAll('Dönemsel Kota', 'Periodic Quota')
        .replaceAll('Aylık Yenilenme', 'Monthly Renewal')
        .replaceAll('Kotası', 'Quota')
        .replaceAll('Kota', 'Quota')
        .replaceAll('Penceresi', 'Window')
        .replaceAll('Pencere', 'Window')
        .replaceAll('Sıfırlanma', 'Resets');
    }

    function translateNote(note) {
      let str = String(note || '');
      if (currentLang === 'tr') return str;
      if (str.includes('Kullanılan:') && str.includes('istek')) {
        str = str.replace('Kullanılan:', 'Used:').replace('istek', 'requests');
      }
      if (str.includes('Kalan:') && str.includes('istek')) {
        str = str.replace('Kalan:', 'Remaining:').replace('istek', 'requests');
      }
      return str
        .replaceAll('Son Geçerlilik:', 'Expires:')
        .replaceAll('Toplam Yüklenen:', 'Total Loaded:')
        .replaceAll('Toplam Harcanan:', 'Total Spent:')
        .replaceAll('Nakit Yüklenen:', 'Topped Up Cash:')
        .replaceAll('Hediye/Promosyon:', 'Granted/Promo:')
        .replaceAll('Hesap kullanım dışı', 'Account inactive')
        .replaceAll('Hesap aktif', 'Account active')
        .replaceAll('Aralık:', 'Interval:')
        .replaceAll('adet kullanılabilir reset hakkı', 'available reset credit(s)')
        .replaceAll('Sınırsız Plan', 'Unlimited Plan')
        .replaceAll('Free tier hesabı', 'Free tier account')
        .replaceAll('Plan: free', 'Plan: Free')
        .replaceAll('Plan: plus', 'Plan: Plus');
    }

    function applyLightDarkMode(mode) {
      currentMode = mode;
      localStorage.setItem('usage_mode', mode);
      const isDark = mode === 'dark';
      document.documentElement.classList.toggle('dark', isDark);
      document.documentElement.classList.toggle('light', !isDark);
      const icon = document.getElementById('lightDarkIcon');
      if (icon) icon.innerText = isDark ? '☀️' : '🌙';
    }

    function toggleLightDark() {
      applyLightDarkMode(currentMode === 'dark' ? 'light' : 'dark');
    }

    function applyAccent(accentKey) {
      currentAccent = accentKey;
      localStorage.setItem('usage_accent', accentKey);
      const pal = THEME_ACCENTS[accentKey] || THEME_ACCENTS.amber;
      const root = document.documentElement;
      root.style.setProperty('--color-accent', pal.accent);
      root.style.setProperty('--color-accent-hover', pal.accentHover);
      root.style.setProperty('--color-accent-soft', pal.accentSoft);

      Object.keys(THEME_ACCENTS).forEach(k => {
        const btn = document.getElementById('themeOpt_' + k);
        if (btn) {
          btn.style.borderColor = k === accentKey ? 'var(--color-accent)' : 'var(--color-border)';
        }
      });
    }

    function changeTheme(accentKey) {
      applyAccent(accentKey);
    }

    function updateSyncStatus() {
      const statusEl = document.getElementById('headerSyncStatus');
      const dotEl = document.getElementById('syncLiveDot');
      if (!statusEl) return;
      const elapsedSec = Math.max(0, Math.floor((Date.now() - lastPolledAt) / 1000));
      let text = '';
      if (elapsedSec < 5) {
        text = t('syncStatusJustNow');
      } else if (elapsedSec < 60) {
        text = t('syncStatusSec').replace('{n}', elapsedSec);
      } else {
        const min = Math.floor(elapsedSec / 60);
        text = t('syncStatusMin').replace('{n}', min);
      }
      statusEl.innerText = text;
      if (dotEl) dotEl.title = text;
    }

    function updateEditButtonState() {
      const btn = document.getElementById('editModeBtn');
      if (!btn) return;
      if (currentGroup !== 'none') {
        btn.disabled = true;
        btn.classList.add('opacity-40', 'cursor-not-allowed');
        btn.title = t('editDisabledGrouped');
      } else {
        btn.disabled = false;
        btn.classList.remove('opacity-40', 'cursor-not-allowed');
        btn.title = t('editModeTitle');
      }
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key && key !== 'loading') {
          el.innerHTML = t(key);
        }
      });
      document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (key) el.title = t(key);
      });
      document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key) el.placeholder = t(key);
      });
      const flagEl = document.getElementById('langFlag');
      if (flagEl && I18N[currentLang]) flagEl.innerText = I18N[currentLang].flag;
      const labelEl = document.getElementById('langLabel');
      if (labelEl) labelEl.innerText = currentLang.toUpperCase();
      const accInput = document.getElementById('accountLabel');
      if (accInput) accInput.placeholder = t('accountLabelPlaceholder');
      updateSecretHelp();
      updateSyncStatus();
      updateEditButtonState();
      if (cachedReports.length) renderCards(cachedReports);
    }
    function toggleLang() {
      currentLang = currentLang === 'tr' ? 'en' : 'tr';
      localStorage.setItem('usage_lang', currentLang);
      applyI18n();
    }

    // Modal controls
    function openModal() {
      document.getElementById('modal').classList.remove('hidden');
      document.getElementById('modal').classList.add('flex');
      updateSecretHelp();
    }
    function closeModal() {
      document.getElementById('modal').classList.add('hidden');
      document.getElementById('modal').classList.remove('flex');
      cancelDeviceAuth();
      cancelBrowserAuth();
    }

    function updateSecretHelp(provider) {
      const p = provider || (document.getElementById('providerSelect') ? document.getElementById('providerSelect').value : 'antigravity');
      const input = document.getElementById('secretValue');
      const help = document.getElementById('secretHelpText');
      const typeSelect = document.getElementById('credentialType');

      const hints = {
        'antigravity': {
          placeholder: currentLang === 'tr' ? 'ya29... veya OAuth Token' : 'ya29... or OAuth Token',
          help: currentLang === 'tr' ? 'Google OAuth Access Token veya Refresh Token' : 'Google OAuth Access Token or Refresh Token',
          type: 'oauth'
        },
        'openai-codex': {
          placeholder: currentLang === 'tr' ? 'OpenAI Access Token (eyJ...)' : 'OpenAI Access Token (eyJ...)',
          help: currentLang === 'tr' ? 'OpenAI Bearer Access Token' : 'OpenAI Bearer Access Token',
          type: 'oauth'
        },
        'github-copilot': {
          placeholder: currentLang === 'tr' ? 'gho_... veya GitHub Personal Token' : 'gho_... or GitHub Personal Token',
          help: currentLang === 'tr' ? 'GitHub Copilot yetkili erişim tokenı' : 'GitHub Copilot authorization token',
          type: 'oauth'
        },
        'cursor': {
          placeholder: currentLang === 'tr' ? 'WorkosCursorSessionToken veya access token' : 'WorkosCursorSessionToken or access token',
          help: currentLang === 'tr' ? 'Cursor oturum tokenı veya çerezi' : 'Cursor session token or cookie',
          type: 'oauth'
        },
        'openrouter': {
          placeholder: currentLang === 'tr' ? 'sk-or-v1-... API Anahtarı' : 'sk-or-v1-... API Key',
          help: currentLang === 'tr' ? 'OpenRouter API Anahtarı' : 'OpenRouter API Key',
          type: 'api_key'
        },
        'deepseek': {
          placeholder: currentLang === 'tr' ? 'sk-... DeepSeek API Anahtarı' : 'sk-... DeepSeek API Key',
          help: currentLang === 'tr' ? 'DeepSeek Platform API Anahtarı' : 'DeepSeek Platform API Key',
          type: 'api_key'
        },
        'xai-oauth': {
          placeholder: currentLang === 'tr' ? 'xAI OAuth Bearer Token veya API Anahtarı' : 'xAI OAuth Bearer Token or API Key',
          help: currentLang === 'tr' ? 'xAI Grok CLI OAuth Tokenı' : 'xAI Grok CLI OAuth Token',
          type: 'oauth'
        },
        'zai': {
          placeholder: currentLang === 'tr' ? 'Zhipu API Anahtarı veya OAuth Token' : 'Zhipu API Key or OAuth Token',
          help: currentLang === 'tr' ? 'Zhipu AI / GLM erişim anahtarı' : 'Zhipu AI / GLM access key or token',
          type: 'oauth'
        },
        'anthropic': {
          placeholder: currentLang === 'tr' ? 'sk-ant-... veya Claude OAuth Token' : 'sk-ant-... or Claude OAuth Token',
          help: currentLang === 'tr' ? 'Anthropic API Anahtarı veya Claude Code Tokenı' : 'Anthropic API Key or Claude Code Token',
          type: 'oauth'
        },
        'devin': {
          placeholder: currentLang === 'tr' ? 'Devin CLI Token veya API Anahtarı' : 'Devin CLI Token or API Key',
          help: currentLang === 'tr' ? 'Devin oturum tokenı' : 'Devin session token',
          type: 'oauth'
        },
        'minimax-code': {
          placeholder: currentLang === 'tr' ? 'MiniMax API Key veya Token' : 'MiniMax API Key or Token',
          help: currentLang === 'tr' ? 'MiniMax Code token plan erişim anahtarı' : 'MiniMax Code token-plan access key',
          type: 'api_key'
        },
        'cline-pass': {
          placeholder: 'ClinePass API Key',
          help: currentLang === 'tr' ? 'Cline kullanım kotası API anahtarı' : 'Cline usage quota API key',
          type: 'api_key'
        },
        'umans': {
          placeholder: 'Umans API Key',
          help: currentLang === 'tr' ? 'Umans Code kullanım API anahtarı' : 'Umans Code usage API key',
          type: 'api_key'
        },
        'google-gemini-cli': {
          placeholder: 'Google OAuth Access Token',
          help: currentLang === 'tr' ? 'Gemini CLI OAuth erişim tokenı' : 'Gemini CLI OAuth access token',
          type: 'oauth'
        },
        'kimi-code': {
          placeholder: 'Kimi Code OAuth Token',
          help: currentLang === 'tr' ? 'Kimi Code abonelik OAuth tokenı; standart Moonshot API key kabul edilmez' : 'Kimi Code subscription OAuth token; standard Moonshot API keys are not accepted',
          type: 'oauth'
        },
        'opencode-go': {
          placeholder: 'OpenCode Go API Key',
          help: currentLang === 'tr' ? 'Aktif OpenCode Go aboneliği API anahtarı' : 'API key for an active OpenCode Go subscription',
          type: 'api_key'
        },
        'alibaba-token-plan': {
          placeholder: currentLang === 'tr' ? 'Alibaba Token Plan Key / Cookie' : 'Alibaba Token Plan Key / Cookie',
          help: currentLang === 'tr' ? 'Bailian/Qwen token plan anahtarı veya konsol oturumu' : 'Bailian/Qwen token-plan key or console session',
          type: 'api_key'
        }
      };
      const h = hints[p] || {
        placeholder: currentLang === 'tr' ? 'Secret veya API Anahtarı' : 'Secret or API Key',
        help: currentLang === 'tr' ? 'Sağlayıcı erişim anahtarı' : 'Provider access credential',
        type: 'api_key'
      };
      if (input) input.placeholder = h.placeholder;
      if (help) help.innerText = h.help;
      if (typeSelect) typeSelect.value = h.type;
    }

    function openSettingsModal() { document.getElementById('settingsModal').classList.remove('hidden'); document.getElementById('settingsModal').classList.add('flex'); }
    function closeSettingsModal() { document.getElementById('settingsModal').classList.add('hidden'); document.getElementById('settingsModal').classList.remove('flex'); }


    function toggleEditMode() {
      if (currentGroup !== 'none') return;
      isEditMode = !isEditMode;
      window.isEditMode = isEditMode;
      editingCardId = null;

      const select = document.getElementById('sortSelect');
      if (isEditMode) {
        currentSort = 'custom';
        localStorage.setItem('usage_sort', 'custom');
        if (select) {
          select.value = 'custom';
          select.disabled = true;
          select.classList.add('opacity-50', 'cursor-not-allowed');
        }
      } else {
        if (select) {
          select.disabled = false;
          select.classList.remove('opacity-50', 'cursor-not-allowed');
        }
      }
      const btn = document.getElementById('editModeBtn');
      const notice = document.getElementById('editModeNotice');
      if (btn) {
        btn.classList.toggle('bg-appAccent', isEditMode);
        btn.classList.toggle('text-zinc-950', isEditMode);
        btn.classList.toggle('bg-appSurface', !isEditMode);
        btn.classList.toggle('text-appTextMuted', !isEditMode);
      }
      if (notice) {
        notice.classList.toggle('hidden', !isEditMode);
      }
      renderCards(cachedReports);
    }

    function changeGroup(groupKey) {
      currentGroup = groupKey === 'provider' ? 'provider' : 'none';
      localStorage.setItem('usage_group', currentGroup);
      const select = document.getElementById('groupSelect');
      if (select) select.value = currentGroup;
      if (currentGroup !== 'none' && isEditMode) {
        isEditMode = false;
        editingCardId = null;
      }
      updateEditButtonState();
      renderCards(cachedReports);
    }

    function changeSort(sortKey) {
      if (isEditMode) return;
      const allowed = ['custom', 'date_added', 'highest_available', 'lowest_available'];
      currentSort = allowed.includes(sortKey) ? sortKey : 'custom';
      localStorage.setItem('usage_sort', currentSort);
      renderCards(cachedReports);
    }

    function switchTab(tab) {
      const isOAuth = tab === 'oauth';
      document.getElementById('oauthSection').classList.toggle('hidden', !isOAuth);
      document.getElementById('manualSection').classList.toggle('hidden', isOAuth);

      document.getElementById('tabOAuth').className = isOAuth
        ? 'flex-1 py-2 font-semibold rounded-lg bg-appSurface text-appText shadow-sm transition'
        : 'flex-1 py-2 font-semibold rounded-lg text-appTextMuted hover:text-appText transition';

      document.getElementById('tabManual').className = !isOAuth
        ? 'flex-1 py-2 font-semibold rounded-lg bg-appSurface text-appText shadow-sm transition'
        : 'flex-1 py-2 font-semibold rounded-lg text-appTextMuted hover:text-appText transition';
    }

    async function loadUsage() {
      try {
        const [dataRes, credsRes] = await Promise.all([
          fetch('/api/data'),
          fetch('/api/credentials').catch(() => null)
        ]);
        if (dataRes.ok) {
          const dataJson = await dataRes.json();
          let reports = dataJson.data || [];
          if (credsRes && credsRes.ok) {
            try {
              const credsJson = await credsRes.json();
              const credsList = credsJson.data || [];
              const credsMap = {};
              credsList.forEach(c => { credsMap[c.id] = c; });
              reports = reports.map(r => {
                const cr = r.credentialId ? credsMap[r.credentialId] : null;
                const dbAccent = (cr && cr.accent) ? cr.accent : (r.accent || 'default');
                return {
                  ...r,
                  createdAt: r.createdAt || (cr ? cr.createdAt : undefined),
                  accent: dbAccent
                };
              });
            } catch {}
          }
          cachedReports = reports;
          lastPolledAt = Date.now();
          updateSyncStatus();
          updateSummary(cachedReports);
          renderCards(cachedReports);
        }
      } catch (err) {
        console.warn('Silent live sync failure:', err);
      }
    }

    function updateSummary(reports) {
      if (!Array.isArray(reports)) return;
      const countEl = document.getElementById('statActiveCount');
      if (countEl) countEl.innerText = reports.length;
      let totalBal = 0;
      let exhausted = 0;

      reports.forEach(r => {
        if (!r) return;
        (r.limits || []).forEach(l => {
          if (!l || !l.amount) return;
          if (l.amount.unit === 'usd' && typeof l.amount.remaining === 'number') {
            const id = String(l.id || '');
            if (id.includes('balance') || id.includes('credits')) totalBal += l.amount.remaining;
          }
          if (l.status === 'exhausted') exhausted++;
        });
      });

      const balEl = document.getElementById('statTotalBalance');
      if (balEl) balEl.innerText = '$' + totalBal.toFixed(2);
      const exhEl = document.getElementById('statExhaustedCount');
      if (exhEl) exhEl.innerText = exhausted;
    }

    async function pollNow() {
      const spinner = document.getElementById('pollSpinner');
      if (spinner) spinner.classList.remove('hidden');
      try {
        await fetch('/api/poll', { method: 'POST' });
        await loadUsage();
      } finally {
        if (spinner) spinner.classList.add('hidden');
      }
    }

    // OAuth flow control
    let currentOAuthTimer = null;

    function cancelDeviceAuth() {
      if (currentOAuthTimer) { clearInterval(currentOAuthTimer); currentOAuthTimer = null; }
      const panel = document.getElementById('deviceAuthPanel');
      if (panel) panel.classList.add('hidden');
      const list = document.getElementById('oauthProvidersList');
      if (list) list.classList.remove('hidden');
    }

    function cancelBrowserAuth() {
      if (currentOAuthTimer) { clearInterval(currentOAuthTimer); currentOAuthTimer = null; }
      const panel = document.getElementById('browserAuthPanel');
      if (panel) panel.classList.add('hidden');
      const list = document.getElementById('oauthProvidersList');
      if (list) list.classList.remove('hidden');
    }

    async function copyDeviceCode() {
      const code = document.getElementById('deviceUserCode')?.innerText;
      if (!code) return;
      try {
        await navigator.clipboard.writeText(code);
        const btnText = document.getElementById('copyBtnText');
        if (btnText) {
          const old = btnText.innerText;
          btnText.innerText = currentLang === 'tr' ? 'Kopyalandı!' : 'Copied!';
          setTimeout(() => { btnText.innerText = old; }, 2000);
        }
      } catch (err) {
        console.warn('Clipboard copy failed:', err);
      }
    }

    async function startBrowserOAuth(endpoint, providerName, badgeName) {
      cancelDeviceAuth();
      cancelBrowserAuth();
      const list = document.getElementById('oauthProvidersList');
      const panel = document.getElementById('browserAuthPanel');
      const textEl = document.getElementById('browserAuthText');
      const linkEl = document.getElementById('browserAuthLink');

      if (list) list.classList.add('hidden');
      if (panel) panel.classList.remove('hidden');
      if (textEl) {
        textEl.innerText = currentLang === 'tr'
          ? (providerName + ' yetkilendirmesi bekleniyor...')
          : ('Waiting for ' + providerName + ' authorization...');
      }

      try {
        const res = await fetch('/api/oauth/' + endpoint + '/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) {
          cancelBrowserAuth();
          alert((currentLang === 'tr' ? 'Hata: ' : 'Error: ') + json.error);
          return;
        }

        const { authUrl, sessionId } = json.data;
        if (linkEl) linkEl.href = authUrl;
        window.open(authUrl, '_blank');

        currentOAuthTimer = setInterval(async () => {
          try {
            const statusRes = await fetch('/api/oauth/status/' + sessionId);
            const statusJson = await statusRes.json();

            if (statusJson.status === 'complete') {
              cancelBrowserAuth();
              closeModal();
              pollNow();
            } else if (statusJson.status === 'error') {
              cancelBrowserAuth();
              alert((currentLang === 'tr' ? 'Yetkilendirme hatası: ' : 'Authorization error: ') + statusJson.error);
            }
          } catch (e) {
            console.warn('Browser OAuth status check failed:', e);
          }
        }, 2000);
      } catch (err) {
        cancelBrowserAuth();
        alert((currentLang === 'tr' ? 'Bağlantı hatası: ' : 'Network error: ') + err);
      }
    }

    // 1. Google Antigravity
    function startGoogleOAuth() {
      startBrowserOAuth('google', 'Google Antigravity', 'Google');
    }

    // 2. OpenAI ChatGPT / Codex
    async function startCodexOAuth() {
      cancelBrowserAuth();
      cancelDeviceAuth();
      const list = document.getElementById('oauthProvidersList');
      const panel = document.getElementById('deviceAuthPanel');
      const badge = document.getElementById('deviceProviderBadge');
      const codeEl = document.getElementById('deviceUserCode');
      const linkEl = document.getElementById('deviceAuthLink');

      if (badge) badge.innerText = 'OpenAI';
      if (list) list.classList.add('hidden');
      if (panel) panel.classList.remove('hidden');

      try {
        const res = await fetch('/api/oauth/codex/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) {
          cancelDeviceAuth();
          alert('Codex error: ' + json.error);
          return;
        }

        const { userCode, verificationUrl, deviceAuthId, interval } = json.data;
        if (codeEl) codeEl.innerText = userCode;
        if (linkEl) linkEl.href = verificationUrl;

        try { await navigator.clipboard.writeText(userCode); } catch {}
        window.open(verificationUrl, '_blank');

        currentOAuthTimer = setInterval(async () => {
          try {
            const pollRes = await fetch('/api/oauth/codex/poll', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ deviceAuthId, userCode })
            });
            const pollJson = await pollRes.json();

            if (pollJson.status === 'complete') {
              cancelDeviceAuth();
              closeModal();
              pollNow();
            } else if (pollJson.status === 'error') {
              cancelDeviceAuth();
              alert((currentLang === 'tr' ? 'Giriş başarısız: ' : 'Login failed: ') + pollJson.error);
            }
          } catch (e) {
            console.warn('Codex poll error:', e);
          }
        }, (interval || 5) * 1000);
      } catch (err) {
        cancelDeviceAuth();
        alert('Codex error: ' + err);
      }
    }

    // 3. Anthropic Claude
    function startClaudeOAuth() {
      startBrowserOAuth('claude', 'Anthropic Claude', 'Anthropic');
    }

    // 4. GitHub Copilot
    async function startCopilotOAuth() {
      cancelBrowserAuth();
      cancelDeviceAuth();
      const list = document.getElementById('oauthProvidersList');
      const panel = document.getElementById('deviceAuthPanel');
      const badge = document.getElementById('deviceProviderBadge');
      const codeEl = document.getElementById('deviceUserCode');
      const linkEl = document.getElementById('deviceAuthLink');

      if (badge) badge.innerText = 'GitHub Copilot';
      if (list) list.classList.add('hidden');
      if (panel) panel.classList.remove('hidden');

      try {
        const res = await fetch('/api/oauth/copilot/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) {
          cancelDeviceAuth();
          alert('Copilot error: ' + json.error);
          return;
        }

        const { userCode, verificationUri, verificationUrl, deviceCode, interval } = json.data;
        const targetUrl = verificationUri || verificationUrl || 'https://github.com/login/device';
        if (codeEl) codeEl.innerText = userCode;
        if (linkEl) linkEl.href = targetUrl;

        try { await navigator.clipboard.writeText(userCode); } catch {}
        window.open(targetUrl, '_blank');

        currentOAuthTimer = setInterval(async () => {
          try {
            const pollRes = await fetch('/api/oauth/copilot/poll', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ deviceCode })
            });
            const pollJson = await pollRes.json();

            if (pollJson.status === 'complete') {
              cancelDeviceAuth();
              closeModal();
              pollNow();
            } else if (pollJson.status === 'error') {
              cancelDeviceAuth();
              alert((currentLang === 'tr' ? 'Copilot yetkilendirme hatası: ' : 'Copilot error: ') + pollJson.error);
            }
          } catch (e) {
            console.warn('Copilot poll error:', e);
          }
        }, (interval || 5) * 1000);
      } catch (err) {
        cancelDeviceAuth();
        alert('Copilot error: ' + err);
      }
    }

    // 5. Cursor
    async function startCursorOAuth() {
      cancelBrowserAuth();
      cancelDeviceAuth();
      const list = document.getElementById('oauthProvidersList');
      const panel = document.getElementById('browserAuthPanel');
      const textEl = document.getElementById('browserAuthText');
      const linkEl = document.getElementById('browserAuthLink');

      if (list) list.classList.add('hidden');
      if (panel) panel.classList.remove('hidden');
      if (textEl) {
        textEl.innerText = currentLang === 'tr' ? 'Cursor yetkilendirmesi bekleniyor...' : 'Waiting for Cursor authorization...';
      }

      try {
        const res = await fetch('/api/oauth/cursor/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) {
          cancelBrowserAuth();
          alert('Cursor error: ' + json.error);
          return;
        }

        const { authUrl, uuid, verifier, interval } = json.data;
        if (linkEl) linkEl.href = authUrl;
        window.open(authUrl, '_blank');

        currentOAuthTimer = setInterval(async () => {
          try {
            const pollRes = await fetch('/api/oauth/cursor/poll', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ uuid, verifier })
            });
            const pollJson = await pollRes.json();

            if (pollJson.status === 'complete') {
              cancelBrowserAuth();
              closeModal();
              pollNow();
            } else if (pollJson.status === 'error') {
              cancelBrowserAuth();
              alert((currentLang === 'tr' ? 'Cursor hatası: ' : 'Cursor error: ') + pollJson.error);
            }
          } catch (e) {
            console.warn('Cursor poll error:', e);
          }
        }, (interval || 2) * 1000);
      } catch (err) {
        cancelBrowserAuth();
        alert('Cursor error: ' + err);
      }
    }

    // 6. xAI Grok
    async function startXaiOAuth() {
      cancelBrowserAuth();
      cancelDeviceAuth();
      const list = document.getElementById('oauthProvidersList');
      const panel = document.getElementById('deviceAuthPanel');
      const badge = document.getElementById('deviceProviderBadge');
      const codeEl = document.getElementById('deviceUserCode');
      const linkEl = document.getElementById('deviceAuthLink');

      if (badge) badge.innerText = 'xAI Grok';
      if (list) list.classList.add('hidden');
      if (panel) panel.classList.remove('hidden');

      try {
        const res = await fetch('/api/oauth/xai/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) {
          cancelDeviceAuth();
          alert('xAI error: ' + json.error);
          return;
        }

        const { userCode, verificationUrl, deviceCode, interval } = json.data;
        if (codeEl) codeEl.innerText = userCode;
        if (linkEl) linkEl.href = verificationUrl;

        try { await navigator.clipboard.writeText(userCode); } catch {}
        window.open(verificationUrl, '_blank');

        currentOAuthTimer = setInterval(async () => {
          try {
            const pollRes = await fetch('/api/oauth/xai/poll', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ deviceCode })
            });
            const pollJson = await pollRes.json();

            if (pollJson.status === 'complete') {
              cancelDeviceAuth();
              closeModal();
              pollNow();
            } else if (pollJson.status === 'error') {
              cancelDeviceAuth();
              alert((currentLang === 'tr' ? 'xAI hatası: ' : 'xAI error: ') + pollJson.error);
            }
          } catch (e) {
            console.warn('xAI poll error:', e);
          }
        }, (interval || 5) * 1000);
      } catch (err) {
        cancelDeviceAuth();
        alert('xAI error: ' + err);
      }
    }

    // 7. Kimi Code
    async function startKimiOAuth() {
      cancelBrowserAuth();
      cancelDeviceAuth();
      const list = document.getElementById('oauthProvidersList');
      const panel = document.getElementById('deviceAuthPanel');
      const badge = document.getElementById('deviceProviderBadge');
      const codeEl = document.getElementById('deviceUserCode');
      const linkEl = document.getElementById('deviceAuthLink');

      if (badge) badge.innerText = 'Kimi Code';
      if (list) list.classList.add('hidden');
      if (panel) panel.classList.remove('hidden');

      try {
        const res = await fetch('/api/oauth/kimi/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) {
          cancelDeviceAuth();
          alert('Kimi error: ' + json.error);
          return;
        }

        const { userCode, verificationUrl, deviceCode, deviceId, interval } = json.data;
        if (codeEl) codeEl.innerText = userCode;
        if (linkEl) linkEl.href = verificationUrl;

        try { await navigator.clipboard.writeText(userCode); } catch {}
        window.open(verificationUrl, '_blank');

        currentOAuthTimer = setInterval(async () => {
          try {
            const pollRes = await fetch('/api/oauth/kimi/poll', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ deviceCode, deviceId })
            });
            const pollJson = await pollRes.json();

            if (pollJson.status === 'complete') {
              cancelDeviceAuth();
              closeModal();
              pollNow();
            } else if (pollJson.status === 'error') {
              cancelDeviceAuth();
              alert((currentLang === 'tr' ? 'Kimi hatası: ' : 'Kimi error: ') + pollJson.error);
            }
          } catch (e) {
            console.warn('Kimi poll error:', e);
          }
        }, (interval || 5) * 1000);
      } catch (err) {
        cancelDeviceAuth();
        alert('Kimi error: ' + err);
      }
    }

    // 8. Google Gemini CLI
    function startGeminiCliOAuth() {
      startBrowserOAuth('gemini-cli', 'Google Gemini CLI', 'Google');
    }

    // 9. OpenRouter
    function startOpenRouterOAuth() {
      startBrowserOAuth('openrouter', 'OpenRouter', 'OpenRouter');
    }

    // 10. Zhipu AI (GLM)
    function startZaiOAuth() {
      startBrowserOAuth('zai', 'Zhipu AI (GLM)', 'Zhipu AI');
    }

    // 11. Devin AI
    function startDevinOAuth() {
      startBrowserOAuth('devin', 'Devin AI', 'Devin');
    }
    async function handleManualSave(e) {
      e.preventDefault();
      const body = {
        provider: document.getElementById('providerSelect').value,
        accountLabel: document.getElementById('accountLabel').value,
        credentialType: document.getElementById('credentialType').value,
        secret: document.getElementById('secretValue').value,
        accent: document.getElementById('accountAccentSelect').value || null
      };
      const submitBtn = e.target.querySelector("button[type='submit']");
      const oldBtnText = submitBtn ? submitBtn.innerText : '';
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerText = currentLang === 'tr' ? 'Doğrulanıyor...' : 'Verifying...';
      }
      try {
        const res = await fetch('/api/credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const json = await res.json();
        if (!res.ok || !json.success) {
          alert((currentLang === 'tr' ? 'Doğrulama Hatası: ' : 'Validation Error: ') + (json.error || 'Bilinmeyen hata'));
          return;
        }
        closeModal();
        document.getElementById('secretValue').value = '';
        setTimeout(pollNow, 300);
      } catch (err) {
        alert((currentLang === 'tr' ? 'Bağlantı Hatası: ' : 'Connection Error: ') + err);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerText = oldBtnText;
        }
      }
    }

    function startEditingLabel(cardKey) {
      editingCardId = cardKey;
      renderCards(cachedReports);
      const input = document.getElementById('editLabelInput_' + cardKey);
      if (input) {
        input.focus();
        input.select();
      }
    }

    function cancelEditingLabel() {
      editingCardId = null;
      renderCards(cachedReports);
    }

    async function saveAccountLabel(cardKey, newLabel) {
      const trimmed = (newLabel || '').trim();
      if (!cardKey || !trimmed) {
        editingCardId = null;
        renderCards(cachedReports);
        return;
      }
      try {
        const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accountLabel: trimmed })
        });
        const json = await res.json();
        if (json.success) {
          const rep = cachedReports.find(r => (r.credentialId || r.provider) === cardKey);
          if (rep) rep.accountLabel = trimmed;
        }
      } catch (err) {
        console.error('Failed to update account label:', err);
      } finally {
        editingCardId = null;
        renderCards(cachedReports);
      }
    }

    async function saveAccountAccent(cardKey, accentKey) {
      if (!cardKey) return;
      const targetAccent = (!accentKey || accentKey === 'null' || accentKey === 'default') ? 'default' : accentKey;
      const rep = cachedReports.find(r => (r.credentialId || r.provider) === cardKey);
      if (rep) rep.accent = targetAccent;
      renderCards(cachedReports);

      try {
        const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accent: targetAccent })
        });
        const json = await res.json();
        if (!json.success) {
          console.warn('Failed to persist accent to server:', json.error);
        }
      } catch (err) {
        console.error('Failed to update account accent:', err);
      }
    }

    // Drag & Drop handlers
    function handleDragStart(e, id) {
      if (!isEditMode || currentGroup !== 'none') return;
      if (currentSort !== 'custom') {
        currentSort = 'custom';
        localStorage.setItem('usage_sort', 'custom');
        const select = document.getElementById('sortSelect');
        if (select) select.value = 'custom';
      }
      draggedCardId = id;
      e.dataTransfer.effectAllowed = 'move';
      e.currentTarget.classList.add('opacity-40');
    }

    function handleDragOver(e) {
      if (!isEditMode || currentGroup !== 'none') return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      e.currentTarget.classList.add('drag-over');
    }

    function handleDragLeave(e) {
      e.currentTarget.classList.remove('drag-over');
    }

    function handleDrop(e, targetId) {
      e.preventDefault();
      e.currentTarget.classList.remove('drag-over');
      if (!isEditMode || currentGroup !== 'none' || !draggedCardId || draggedCardId === targetId) return;

      if (currentSort !== 'custom') {
        currentSort = 'custom';
        localStorage.setItem('usage_sort', 'custom');
        const select = document.getElementById('sortSelect');
        if (select) select.value = 'custom';
      }

      const fromIdx = cachedReports.findIndex(r => (r.credentialId || r.provider) === draggedCardId);
      const toIdx = cachedReports.findIndex(r => (r.credentialId || r.provider) === targetId);
      if (fromIdx === -1 || toIdx === -1) return;

      const [moved] = cachedReports.splice(fromIdx, 1);
      cachedReports.splice(toIdx, 0, moved);

      const customOrder = cachedReports.map(r => r.credentialId || r.provider);
      localStorage.setItem('usage_custom_order', JSON.stringify(customOrder));
      renderCards(cachedReports);
    }

    function handleDragEnd(e) {
      draggedCardId = null;
      document.querySelectorAll('#cardsGrid > div').forEach(el => {
        el.classList.remove('opacity-40', 'drag-over');
      });
    }

    function getReportScore(report) {
      let score = 0;
      for (const l of report.limits || []) {
        if (l.amount?.unit === 'usd' && typeof l.amount.remaining === 'number') {
          return l.amount.remaining * 10;
        }
        if (l.amount?.unit === 'percent' && typeof l.amount.remaining === 'number') {
          return l.amount.remaining;
        }
      }
      return score;
    }

    function sortReports(reports, sortKey) {
      const list = [...reports];
      if (sortKey === 'custom') {
        const saved = localStorage.getItem('usage_custom_order');
        if (saved) {
          try {
            const order = JSON.parse(saved);
            list.sort((a, b) => {
              const idA = a.credentialId || a.provider;
              const idB = b.credentialId || b.provider;
              const idxA = order.indexOf(idA);
              const idxB = order.indexOf(idB);
              if (idxA === -1 && idxB === -1) return 0;
              if (idxA === -1) return 1;
              if (idxB === -1) return -1;
              return idxA - idxB;
            });
            return list;
          } catch {}
        }
      } else if (sortKey === 'date_added') {
        const hasValidCreatedAt = list.some(r => typeof r.createdAt === 'number' && r.createdAt > 0);
        if (hasValidCreatedAt) {
          list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
        }
        return list;
      } else if (sortKey === 'highest_available') {
        list.sort((a, b) => getReportScore(b) - getReportScore(a));
      } else if (sortKey === 'lowest_available') {
        list.sort((a, b) => getReportScore(a) - getReportScore(b));
      }
      return list;
    }

    function renderCardHtml(r) {
      const cardKey = r.credentialId || r.provider;
      const providerTitle = formatProviderTitle(r.provider);
      const metaEmail = r.metadata && (r.metadata.email || r.metadata.login || r.metadata.username || r.metadata.accountId || r.metadata.userId);
      let cleanLabel = (r.accountLabel || 'Default').replace(/^Google \((.*)\)$/, '$1');
      if ((!cleanLabel || cleanLabel.toLowerCase() === providerTitle.toLowerCase() || cleanLabel.toLowerCase() === (r.provider || '').toLowerCase() || cleanLabel === 'Default') && metaEmail) {
        cleanLabel = String(metaEmail);
      }
      const cardAccent = r.accent || 'default';

      const canDrag = isEditMode && currentGroup === 'none';
      const dragAttrs = canDrag
        ? ' draggable="true" ondragstart="handleDragStart(event, this.dataset.cardId)" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event, this.dataset.cardId)" ondragend="handleDragEnd(event)"'
        : '';

      const editBorderClass = isEditMode
        ? ' is-edit-mode cursor-grab active:cursor-grabbing'
        : ' hover:border-zinc-700';

      const hasLimits = Array.isArray(r.limits) && r.limits.length > 0;
      const isStale = Boolean(
        r.stale ||
        r.health === 'stale' ||
        r.source === 'stale' ||
        (Boolean(r.error) && hasLimits)
      );
      const isFirstError = Boolean(
        (r.health === 'error' || r.error) && !isStale && !hasLimits
      );
      const cardStatus = isStale ? 'stale' : (isFirstError ? 'error' : 'healthy');

      const successTimestamp = (isStale && r.lastGoodFetchedAt) ? r.lastGoodFetchedAt : r.fetchedAt;
      const timeStr = successTimestamp ? new Date(successTimestamp).toLocaleTimeString() : '';
      const updateLabel = isStale ? t('lastSuccessfulUpdate') : (t('lastUpdate') + ':');

      const staleBadgeHtml = isStale ? (
        '<span data-status="stale" class="account-card-stale-badge bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-medium px-1.5 py-0.5 rounded flex items-center gap-1 shrink-0" title="' + escapeHtml(t('staleNotice')) + '">' +
        '  <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>' +
        '  <span data-i18n="staleBadge">' + escapeHtml(t('staleBadge')) + '</span>' +
        '</span>'
      ) : '';

      const rawError = getLocalizedReportError(r);
      let statusNoticeHtml = '';

      if (isStale) {
        const errorDesc = rawError ? ('<span class="text-[11px] text-amber-400/90 block truncate">' + escapeHtml(rawError) + '</span>') : '';
        statusNoticeHtml =
          '<div data-stale-notice="true" role="status" aria-live="polite" class="account-card-stale-notice bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs px-3 py-2 rounded-xl flex items-start gap-2.5">' +
          '  <svg class="w-4 h-4 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
          '  <div class="flex-1 space-y-0.5 min-w-0">' +
          '    <div class="font-medium flex items-center justify-between gap-2 flex-wrap">' +
          '      <span data-i18n="staleNotice">' + escapeHtml(t('staleNotice')) + '</span>' +
          '      <span class="text-[11px] text-amber-400/80 font-normal">' + escapeHtml(t('lastSuccessfulUpdate')) + ' ' + escapeHtml(timeStr) + '</span>' +
          '    </div>' +
          '    ' + errorDesc +
          '  </div>' +
          '</div>';
      } else if (isFirstError) {
        const displayErr = rawError || t('initialUnavailable');
        statusNoticeHtml =
          '<div data-status="error" class="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs px-3 py-2 rounded-xl flex items-center gap-2">' +
          '  <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
          '  <span class="truncate">' + escapeHtml(displayErr) + '</span>' +
          '</div>';
      }

      const limitsHtml = (r.limits || []).map(l => {
        let valueHtml = '';
        let barHtml = '';

        if (l.amount.unit === 'percent') {
          const used = l.amount.used || 0;
          const isCritical = used >= 90;
          const barColor = isCritical ? 'bg-rose-500' : 'account-card-bar-fill';
          valueHtml = '<span class="account-card-value font-bold text-sm">' + used.toFixed(1) + '%</span>';
          barHtml = '<div class="w-full account-card-bar-track h-1.5 rounded-full overflow-hidden mt-2"><div class="' + barColor + ' h-full transition-all duration-300" style="width: ' + Math.min(100, used) + '%"></div></div>';
        } else if (l.amount.unit === 'usd') {
          const rem = l.amount.remaining ?? 0;
          valueHtml = '<span class="account-card-value font-bold text-sm">$' + rem.toFixed(2) + '</span>';
        } else if (l.amount.unit === 'credits') {
          const rem = l.amount.remaining ?? 0;
          const labelText = currentLang === 'tr' ? (rem + ' Hak Mevcut') : (rem + ' Available');
          valueHtml = '<span class="account-card-badge font-semibold text-xs px-2.5 py-0.5 rounded-md">' + labelText + '</span>';
        }

        let countdownHtml = '';
        if (l.window && l.window.resetsAt) {
          const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
          const hours = Math.floor(diffMin / 60);
          const mins = diffMin % 60;
          const timeLabel = currentLang === 'tr'
            ? (hours > 0 ? (hours + 'sa ' + mins + 'dk') : (mins + 'dk'))
            : (hours > 0 ? (hours + 'h ' + mins + 'm') : (mins + 'm'));
          countdownHtml = '<span class="text-xs text-appTextMuted flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-appTextMuted/70"></span>' + t('resetsIn') + ': ' + timeLabel + '</span>';
        }

        const cleanLabel = translateLimitLabel(l.label, l.id);
        const cleanNotes = (l.notes || []).filter(n => !String(n).toLowerCase().includes('model') && !String(n).toLowerCase().startsWith('plan:'));
        const notesHtml = cleanNotes.map(n => '<span class="text-xs text-appTextMuted block mt-0.5">' + translateNote(n) + '</span>').join('');

        return '<div class="account-card-box border rounded-xl p-3.5 space-y-1.5">' +
               '  <div class="flex justify-between items-center">' +
               '    <span class="text-sm font-semibold text-appText tracking-tight">' + cleanLabel + '</span>' +
               '    ' + valueHtml +
               '  </div>' +
               barHtml +
               '  <div class="flex justify-between items-center pt-1">' +
               countdownHtml +
               '  </div>' +
               notesHtml +
               '</div>';
      }).join('');

      const planNote = (r.limits || []).flatMap(l => l.notes || []).find(n => String(n).toLowerCase().startsWith('plan:'));
      const rawPlan = r.metadata?.planType || (planNote ? planNote.replace(/^Plan:\s*/i, '').trim() : '');
      const planName = rawPlan ? rawPlan.toUpperCase() : '';
      const planBadgeHtml = planName
        ? '<span class="px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider rounded-md bg-appAccentSoft text-appAccent border border-appAccent/30 shadow-xs">' + escapeHtml(planName) + '</span>'
        : '';

      let labelDisplayHtml = '';
      if (isEditMode) {
        if (editingCardId === cardKey) {
          labelDisplayHtml =
            '<div class="flex items-center gap-1.5 mt-1" draggable="false" onmousedown="event.stopPropagation()">' +
            '  <input type="text" id="editLabelInput_' + cardKey + '" data-key="' + cardKey + '" value="' + escapeHtml(cleanLabel) + '" class="text-xs px-2.5 py-1 bg-appMuted border border-appAccent rounded-md text-appText outline-none w-36" onkeydown="if(event.key===&quot;Enter&quot;)saveAccountLabel(this.dataset.key, this.value); if(event.key===&quot;Escape&quot;)cancelEditingLabel();" />' +
            '  <button type="button" data-key="' + cardKey + '" onclick="saveAccountLabel(this.dataset.key, document.getElementById(&quot;editLabelInput_&quot; + this.dataset.key).value)" class="px-2 py-1 text-xs bg-appAccent text-zinc-950 font-semibold rounded-md hover:bg-appAccentHover" data-i18n-title="save">✓</button>' +
            '  <button type="button" onclick="cancelEditingLabel()" class="px-2 py-1 text-xs bg-appMuted text-appTextMuted rounded-md hover:text-appText" data-i18n-title="cancel">✕</button>' +
            '</div>';
        } else {
          labelDisplayHtml =
            '<div class="flex items-center gap-2 mt-1" draggable="false" onmousedown="event.stopPropagation()">' +
            '  <span class="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">' + escapeHtml(cleanLabel) + '</span>' +
            '  <button type="button" data-key="' + cardKey + '" onclick="startEditingLabel(this.dataset.key)" class="text-[11px] font-medium text-appAccent hover:underline flex items-center gap-1">' +
            '    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>' +
            '    <span>' + t('editLabel') + '</span>' +
            '  </button>' +
            '</div>';
        }
      } else {
        labelDisplayHtml = '<span class="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">' + escapeHtml(cleanLabel) + '</span>';
      }

      let editAccentHtml = '';
      if (isEditMode) {
        const a = r.accent || 'default';
        editAccentHtml =
          '<div class="pt-2 border-t border-appBorder/50 flex items-center justify-between text-xs" draggable="false" onmousedown="event.stopPropagation()">' +
          '  <span class="text-[11px] font-semibold text-appTextMuted">' + t('cardAccent') + ':</span>' +
          '  <div class="flex items-center gap-1.5">' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="default" onclick="saveAccountAccent(this.dataset.key, &quot;default&quot;)" title="' + t('accentDefault') + '" class="w-4 h-4 rounded-full border border-appBorder bg-transparent relative flex items-center justify-center ' + (!a || a === 'default' ? 'ring-2 ring-appAccent ring-offset-1 ring-offset-appSurface' : '') + '"><span class="w-1.5 h-1.5 rounded-full bg-appTextMuted/40"></span></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="amber" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Amber" class="w-4 h-4 rounded-full bg-[#ff9849] ' + (a === 'amber' ? 'ring-2 ring-white ring-offset-1 ring-offset-appSurface' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="emerald" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Emerald" class="w-4 h-4 rounded-full bg-[#10b981] ' + (a === 'emerald' ? 'ring-2 ring-white ring-offset-1 ring-offset-appSurface' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="cyan" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Cyan" class="w-4 h-4 rounded-full bg-[#06b6d4] ' + (a === 'cyan' ? 'ring-2 ring-white ring-offset-1 ring-offset-appSurface' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="violet" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Violet" class="w-4 h-4 rounded-full bg-[#a855f7] ' + (a === 'violet' ? 'ring-2 ring-white ring-offset-1 ring-offset-appSurface' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="slate" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Slate" class="w-4 h-4 rounded-full bg-[#38bdf8] ' + (a === 'slate' ? 'ring-2 ring-white ring-offset-1 ring-offset-appSurface' : '') + '"></button>' +
          '  </div>' +
          '</div>';
      }

      return '<div data-card-id="' + cardKey + '" data-status="' + cardStatus + '" data-accent="' + cardAccent + '" class="account-card border ' + editBorderClass + ' rounded-2xl p-5 space-y-4 transition-all shadow-sm relative"' + dragAttrs + '>' +
             '  <div class="flex justify-between items-start">' +
             '    <div>' +
             '      <div class="flex items-center gap-2 flex-wrap">' +
             '        <h2 class="account-card-title font-bold text-base tracking-tight">' + providerTitle + '</h2>' +
             planBadgeHtml +
             labelDisplayHtml +
             staleBadgeHtml +
             '      </div>' +
             '      <span class="text-xs text-appTextMuted block mt-1.5">' + escapeHtml(updateLabel) + ' ' + escapeHtml(timeStr) + '</span>' +
             '    </div>' +
             '  </div>' +
             statusNoticeHtml +
             '  <div class="space-y-2.5">' + limitsHtml + '</div>' +
             editAccentHtml +
             '</div>';
    }

    function renderCards(reports) {
      const container = document.getElementById('cardsGrid');
      if (!container) return;
      if (!reports.length) {
        container.innerHTML = '<div class="col-span-full py-24 text-center text-appTextMuted text-sm">' + t('noAccounts') + '</div>';
        return;
      }

      const effectiveSort = isEditMode ? 'custom' : currentSort;
      const sortedList = sortReports(reports, effectiveSort);

      if (currentGroup === 'provider') {
        const groups = {};
        sortedList.forEach(r => {
          const p = r.provider || 'other';
          if (!groups[p]) groups[p] = [];
          groups[p].push(r);
        });

        let html = '';
        Object.keys(groups).sort().forEach(p => {
          const groupReports = groups[p];
          const providerTitle = formatProviderTitle(p);
          html +=
            '<div class="col-span-full pt-4 first:pt-0 pb-1.5 border-b border-appBorder flex items-center justify-between">' +
            '  <div class="flex items-center gap-2">' +
            '    <span class="font-bold text-sm text-appText tracking-tight">' + providerTitle + '</span>' +
            '    <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-appMuted text-appTextMuted border border-appBorder">' + groupReports.length + '</span>' +
            '  </div>' +
            '</div>';
          html += groupReports.map(renderCardHtml).join('');
        });
        container.innerHTML = html;
      } else {
        container.innerHTML = sortedList.map(renderCardHtml).join('');
      }
    }

    async function deleteAccount(id) {
      if (!id || !confirm(t('deleteConfirm'))) return;
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadUsage();
    }

    // Initialize
    applyLightDarkMode(currentMode);
    applyAccent(currentAccent);
    const sortSelect = document.getElementById('sortSelect');
    if (sortSelect) sortSelect.value = currentSort;
    const groupSelect = document.getElementById('groupSelect');
    if (groupSelect) groupSelect.value = currentGroup;
    applyI18n();
    updateEditButtonState();
    setInterval(loadUsage, 10000);
    setInterval(updateSyncStatus, 1000);
  </script>
</body>
</html>`;
}

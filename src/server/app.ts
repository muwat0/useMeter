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
  DASHBOARD_CSP,
  RateLimiter,
  RATE_LIMIT_POLICIES,
  resolveClientIp,
} from "./security";
import { join } from "path";
import { existsSync, readFileSync, realpathSync, statSync } from "fs";
import { createHash } from "crypto";
import {
  initiateCodexDeviceAuth,
  pollCodexDeviceAuth,
  exchangeCodexToken,
  initiateGoogleAuth,
  exchangeGoogleCode,
  validateGoogleOAuthConfig,
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
  getDevinRedirectUri,
} from "../core/oauth";


const GOOGLE_LOOPBACK_CALLBACK_URI = "http://127.0.0.1:51121/oauth-callback";
const GOOGLE_OAUTH_SESSION_TTL_MS = 10 * 60 * 1000;

interface ParsedGoogleCallback {
  state: string;
  code?: string;
  providerError?: string;
}

function parseGoogleCallbackParameters(params: URLSearchParams): ParsedGoogleCallback | null {
  const seen = new Set<string>();
  for (const [name] of params) {
    if (seen.has(name)) return null;
    seen.add(name);
  }

  const state = params.get("state");
  const code = params.get("code");
  const providerError = params.get("error");
  if (!state?.trim() || (code !== null && !code.trim()) || (providerError !== null && !providerError.trim())) {
    return null;
  }
  if (code !== null && providerError !== null) return null;
  if (providerError !== null) return { state, providerError };
  if (code === null) return null;
  return { state, code };
}

function parseGoogleManualCallbackUrl(value: unknown): ParsedGoogleCallback | null {
  if (typeof value !== "string") return null;
  const input = value.trim();
  if (!input.startsWith(`${GOOGLE_LOOPBACK_CALLBACK_URI}?`) || input.includes("#")) return null;
  try {
    const callback = new URL(input);
    if (
      callback.origin !== "http://127.0.0.1:51121" ||
      callback.pathname !== "/oauth-callback" ||
      callback.username ||
      callback.password ||
      callback.hash
    ) {
      return null;
    }
    return parseGoogleCallbackParameters(callback.searchParams);
  } catch {
    return null;
  }
}

function clearGoogleOAuthSecrets(session: PendingOAuthSession): void {
  session.googleVerifier = undefined;
  session.googleClientId = undefined;
  session.googleClientSecret = undefined;
  session.googleRedirectUri = undefined;
}

function expireGoogleOAuthSession(session: PendingOAuthSession, now: number): boolean {
  if (
    session.provider !== "antigravity" ||
    session.status !== "pending" ||
    session.consumed ||
    session.createdAt === undefined ||
    now - session.createdAt < GOOGLE_OAUTH_SESSION_TTL_MS
  ) {
    return false;
  }
  session.status = "error";
  session.error = "Authorization session expired";
  session.consumed = true;
  clearGoogleOAuthSecrets(session);
  return true;
}

interface PendingOAuthSession {
  provider: string;
  ownerId: string;
  status: "pending" | "complete" | "error";
  error?: string;
  accountLabel?: string;
  googleVerifier?: string;
  googleClientId?: string;
  googleClientSecret?: string;
  googleRedirectUri?: string;
  devinVerifier?: string;
  createdAt?: number;
  consumed?: boolean;
}
interface AppVariables {
  user: User;
  sessionToken: string;
}
export type AppEnv = { Variables: AppVariables };
export type AppContext = Context<AppEnv>;
export type AppInstance = Hono<AppEnv>;

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
  let reqOrigin: string;
  try {
    const requestUrl = new URL(c.req.url);
    reqOrigin = requestUrl.origin;
    const trustProxy = process.env["TRUST_PROXY"] === "true" || process.env["TRUST_PROXY"] === "1";
    if (trustProxy) {
      const forwardedProto = c.req.header("X-Forwarded-Proto")?.split(",")[0]?.trim();
      const forwardedHost = c.req.header("X-Forwarded-Host")?.split(",")[0]?.trim() || c.req.header("Host")?.trim();
      if ((forwardedProto === "http" || forwardedProto === "https") && forwardedHost) {
        reqOrigin = `${forwardedProto}://${forwardedHost}`;
      }
    }
  } catch {
    return false;
  }
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
export interface ServerOptions {
  rateLimiter?: RateLimiter;
  assetRevision?: string;
  distDir?: string;
  googleOAuthExchange?: typeof exchangeGoogleCode;
  googleOAuthNow?: () => number;
}

const DEFAULT_DIST_CLIENT_DIR = join(import.meta.dir, "../../dist/client");

export function computeAssetRevision(distDir: string = DEFAULT_DIST_CLIENT_DIR): string {
  try {
    const hash = createHash("sha256");
    let hasBytes = false;
    for (const filename of ["app.js", "app.css"]) {
      const filePath = join(distDir, filename);
      if (existsSync(filePath)) {
        hash.update(filename);
        hash.update(readFileSync(filePath));
        hasBytes = true;
      }
    }
    return hasBytes ? hash.digest("hex").slice(0, 16) : "";
  } catch {
    return "";
  }
}

let cachedAssetRevision: string | null = null;

export function getAssetRevision(reload = false, distDir: string = DEFAULT_DIST_CLIENT_DIR): string {
  if (cachedAssetRevision === null || reload) {
    cachedAssetRevision = computeAssetRevision(distDir);
  }
  return cachedAssetRevision;
}

export function createServer(
  vault: StorageVault,
  poller: PollerEngine,
  _registry?: ProviderRegistry,
  authService?: AuthService,
  options?: ServerOptions
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
  const googleOAuthExchange = options?.googleOAuthExchange ?? exchangeGoogleCode;
  const googleOAuthNow = options?.googleOAuthNow ?? Date.now;

  async function validateAndSaveGoogleCredential(
    ownerId: string,
    code: string,
    verifier: string,
    config: { clientId: string; clientSecret: string; redirectUri: string },
  ) {
    const tokens = await googleOAuthExchange(code, verifier, config);
    const accountLabel = tokens.email?.trim() || "Antigravity";
    const refreshToken = tokens.refreshToken?.trim() ? tokens.refreshToken : undefined;
    const saved = await poller.validateAndSaveCredential(ownerId, {
      ownerId,
      provider: "antigravity",
      accountLabel,
      credentialType: "oauth",
      secret: tokens.accessToken,
      metadata: {
        refreshToken,
        email: tokens.email,
        ...(refreshToken
          ? {
              googleOAuthClientId: config.clientId,
              googleOAuthClientSecret: config.clientSecret,
            }
          : {}),
      },
    }, "preserve");
    return { saved, accountLabel };
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
    const requestPath = new URL(c.req.url).pathname;
    const csp = requestPath === "/" ? DASHBOARD_CSP : undefined;
    const secHeaders = getSecurityHeaders(secure, { contentSecurityPolicy: csp });
    for (const [k, v] of Object.entries(secHeaders)) {
      c.header(k, v);
    }
    try {
      await next();
    } finally {
      if (c.res) {
        applySecurityHeaders(c.res.headers, secure, { contentSecurityPolicy: csp });
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
      path.startsWith("/assets/") ||
      path === "/api/oauth/google/callback" ||
      path === "/api/oauth/devin/callback" ||
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

  // Static asset serving for React client build
  const ASSET_MIME: Record<string, string> = {
    ".js": "application/javascript",
    ".css": "text/css",
    ".map": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
  };
  const distClientDir = options?.distDir ?? DEFAULT_DIST_CLIENT_DIR;
  const assetRevision = options?.assetRevision ?? (options?.distDir ? computeAssetRevision(distClientDir) : getAssetRevision());

  app.on(["GET", "HEAD"], "/assets/*", async (c) => {
    const rawPath = decodeURIComponent(c.req.path);
    const relPath = rawPath.replace(/^\/assets\//, "");
    if (!relPath || relPath.includes("..") || relPath.includes("\\") || relPath.startsWith("/")) {
      return c.text("Forbidden", 403);
    }
    const filePath = join(distClientDir, relPath);
    let realPath: string;
    try {
      realPath = realpathSync(filePath);
    } catch {
      return c.text("Not Found", 404);
    }
    let realDistDir: string;
    try {
      realDistDir = realpathSync(distClientDir);
    } catch {
      return c.text("Not Found", 404);
    }
    if (!realPath.startsWith(realDistDir + "/")) {
      return c.text("Forbidden", 403);
    }
    const stat = statSync(filePath, { throwIfNoEntry: false });
    if (!stat || !stat.isFile()) {
      return c.text("Not Found", 404);
    }
    const file = Bun.file(filePath);
    const ext = filePath.substring(filePath.lastIndexOf("."));
    const mime = ASSET_MIME[ext] || "application/octet-stream";
    const headers = new Headers({
      "Content-Type": mime,
      "Content-Length": String(file.size),
      "Cache-Control": "public, max-age=31536000, immutable",
    });
    if (c.req.method === "HEAD") {
      return new Response(null, { status: 200, headers });
    }
    return new Response(file, { headers });
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
      const ip = getClientIp(c);
      const rl = rateLimiter.check(`registration:${ip}`, RATE_LIMIT_POLICIES.registration);
      if (!rl.allowed) {
        return rateLimitResponse(c, rl.retryAfterSec, "Too many registration attempts. Please try again later.");
      }

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
      return toPublicUsageReport(report, {
        accountLabel: credential?.accountLabel || report.accountLabel,
        createdAt: credential?.createdAt,
        accent: credential?.accent || "default",
        metadata: credential?.metadata,
      });
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
      const reports: PublicUsageReport[] = [];
      for (const cred of credentials) {
        const report = await poller.pollCredential(user.id, cred.id);
        if (report) {
          reports.push(
            toPublicUsageReport(report, {
              accountLabel: cred.accountLabel,
              createdAt: cred.createdAt,
              accent: cred.accent || "default",
              metadata: cred.metadata,
            })
          );
        }
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
      return c.json({
        success: true,
        data: report
          ? toPublicUsageReport(report, {
              accountLabel: cred.accountLabel,
              createdAt: cred.createdAt,
              accent: cred.accent || "default",
              metadata: cred.metadata,
            })
          : null,
      });
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

      let metadata = body.metadata;
      if (body.accent) {
        metadata = { ...(metadata || {}), accent: body.accent };
      }

      const { ownerId: _, ...inputData } = body;
      let saved;
      try {
        saved = await poller.validateAndSaveCredential(user.id, {
          ...inputData,
          ownerId: user.id,
          metadata,
        }, "replace");
      } catch (validationError) {
        const message = validationError instanceof Error ? validationError.message : String(validationError);
        return c.json({ success: false, error: message }, 400);
      }

      return c.json({
        success: true,
        data: {
          id: saved.id,
          provider: saved.provider,
          accountLabel: saved.accountLabel,
          accent: body.accent || (saved.accent && saved.accent !== "default" ? saved.accent : null),
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

      let saved;
      try {
        saved = await poller.validateAndSaveCredential(user.id, {
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
        }, "preserve");
      } catch (validationError) {
        const message = validationError instanceof Error ? validationError.message : String(validationError);
        return c.json({ status: "error", error: message });
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
      const config = validateGoogleOAuthConfig();
      const { authUrl, verifier, state } = initiateGoogleAuth(config);
      const sessionId = state;
      pendingOAuth.set(sessionId, {
        provider: "antigravity",
        ownerId: user.id,
        status: "pending",
        googleVerifier: verifier,
        googleClientId: config.clientId,
        googleClientSecret: config.clientSecret,
        googleRedirectUri: config.redirectUri,
        createdAt: googleOAuthNow(),
        consumed: false,
      });
      return c.json({
        success: true,
        data: {
          authUrl,
          sessionId,
          redirectUri: config.redirectUri,
          manualCallback: config.redirectUri === GOOGLE_LOOPBACK_CALLBACK_URI,
          expiresIn: GOOGLE_OAUTH_SESSION_TTL_MS / 1000,
        },
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "";
      if (
        msg.includes("Public Google OAuth redirect URI requires custom GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET") ||
        msg.includes("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET must both be provided together") ||
        msg.startsWith("Invalid Google OAuth redirect URI")
      ) {
        return c.json({ success: false, error: msg }, 400);
      }
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: Google loopback callback pasted from the remote browser's address bar.
  app.post("/api/oauth/google/manual", async c => {
    const user = c.get("user");
    const rl = rateLimiter.check(
      `oauthDevicePoll:${user.id}:google-manual`,
      RATE_LIMIT_POLICIES.oauthDevicePoll,
    );
    if (!rl.allowed) {
      return rateLimitResponse(c, rl.retryAfterSec, "Too many authorization attempts. Please slow down.");
    }

    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return c.json({ success: false, error: "Invalid callback request" }, 400);
    }
    const request = body as Record<string, unknown>;
    const sessionId = typeof request["sessionId"] === "string" ? request["sessionId"] : "";
    if (!sessionId) return c.json({ success: false, error: "Invalid callback request" }, 400);

    const session = pendingOAuth.get(sessionId);
    if (!session || session.provider !== "antigravity" || session.ownerId !== user.id) {
      return c.json({ success: false, error: "Invalid or expired authorization session" }, 404);
    }
    if (expireGoogleOAuthSession(session, googleOAuthNow()) || session.createdAt === undefined) {
      return c.json({ success: false, error: "Authorization session expired" }, 400);
    }
    if (session.status !== "pending" || session.consumed) {
      return c.json({ success: false, error: "Authorization response already used" }, 400);
    }

    const callback = parseGoogleManualCallbackUrl(request["callbackInput"]);
    if (!callback || callback.state !== sessionId) {
      return c.json({ success: false, error: "Invalid callback URL" }, 400);
    }
    if (
      !session.googleVerifier ||
      !session.googleClientId ||
      !session.googleClientSecret ||
      session.googleRedirectUri !== GOOGLE_LOOPBACK_CALLBACK_URI
    ) {
      session.status = "error";
      session.error = "Authorization session invalid";
      session.consumed = true;
      clearGoogleOAuthSecrets(session);
      return c.json({ success: false, error: "Invalid or expired authorization session" }, 400);
    }

    const verifier = session.googleVerifier;
    const config = {
      clientId: session.googleClientId,
      clientSecret: session.googleClientSecret,
      redirectUri: session.googleRedirectUri,
    };
    session.consumed = true;
    session.googleVerifier = undefined;

    if (callback.providerError) {
      session.status = "error";
      session.error = "Authorization was denied";
      clearGoogleOAuthSecrets(session);
      return c.json({ success: false, error: "Authorization was denied" }, 400);
    }

    try {
      const { saved, accountLabel } = await validateAndSaveGoogleCredential(
        user.id,
        callback.code!,
        verifier,
        config,
      );
      session.status = "complete";
      session.accountLabel = accountLabel;
      clearGoogleOAuthSecrets(session);
      return c.json({ success: true, data: { id: saved.id, accountLabel } });
    } catch {
      session.status = "error";
      session.error = "Authorization failed";
      clearGoogleOAuthSecrets(session);
      return c.json({ success: false, error: "Authorization failed" }, 400);
    }
  });

  // OAuth: Google Web-client callback.
  app.get("/api/oauth/google/callback", async c => {
    const params = parseGoogleCallbackParameters(new URL(c.req.url).searchParams);
    const session = params ? pendingOAuth.get(params.state) : undefined;
    const successPage = (title: string, message: string, color: string) =>
      c.html(`<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body style="font-family:system-ui,sans-serif;background:#0a0a0b;color:${color};text-align:center;padding:50px"><h2>${title}</h2><p style="color:#a1a1aa">${message}</p><script>setTimeout(()=>window.close(),1500)</script></body></html>`);

    if (!params) return c.html("Invalid authorization response.", 400);
    if (
      !session ||
      session.provider !== "antigravity" ||
      session.googleRedirectUri === GOOGLE_LOOPBACK_CALLBACK_URI
    ) {
      return c.html("Invalid or expired authorization session.", 400);
    }
    if (expireGoogleOAuthSession(session, googleOAuthNow()) || session.createdAt === undefined) {
      return successPage("Google Login Failed", "Authorization session expired. You can close this tab.", "#f43f5e");
    }
    if (session.status !== "pending" || session.consumed) {
      return c.html("Authorization response already used.", 400);
    }
    if (
      !session.googleVerifier ||
      !session.googleClientId ||
      !session.googleClientSecret ||
      !session.googleRedirectUri
    ) {
      session.status = "error";
      session.error = "Authorization session invalid";
      session.consumed = true;
      clearGoogleOAuthSecrets(session);
      return c.html("Invalid or expired authorization session.", 400);
    }

    const verifier = session.googleVerifier;
    const config = {
      clientId: session.googleClientId,
      clientSecret: session.googleClientSecret,
      redirectUri: session.googleRedirectUri,
    };
    session.consumed = true;
    session.googleVerifier = undefined;

    if (params.providerError) {
      session.status = "error";
      session.error = "Authorization was denied";
      clearGoogleOAuthSecrets(session);
      return successPage("Google Login Failed", "Authorization was denied. You can close this tab.", "#f43f5e");
    }

    try {
      const { accountLabel } = await validateAndSaveGoogleCredential(
        session.ownerId,
        params.code!,
        verifier,
        config,
      );
      session.status = "complete";
      session.accountLabel = accountLabel;
      clearGoogleOAuthSecrets(session);
      return successPage("Google Login Successful", "You can close this tab and return to useMeter.", "#10b981");
    } catch {
      session.status = "error";
      session.error = "Authorization failed";
      clearGoogleOAuthSecrets(session);
      return successPage("Google Login Failed", "Authorization failed. You can close this tab.", "#f43f5e");
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
      let saved;
      try {
        saved = await poller.validateAndSaveCredential(user.id, {
          ownerId: user.id,
          provider: "xai-oauth",
          accountLabel: label,
          credentialType: "oauth",
          secret: pollRes.accessToken,
          metadata: {
            refreshToken: pollRes.refreshToken,
            email: pollRes.email,
          },
        }, "preserve");
      } catch (validationError) {
        const message = validationError instanceof Error ? validationError.message : String(validationError);
        return c.json({ status: "error", error: message });
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
      let saved;
      try {
        saved = await poller.validateAndSaveCredential(user.id, {
          ownerId: user.id,
          provider: "kimi-code",
          accountLabel: label,
          credentialType: "oauth",
          secret: pollRes.accessToken,
          metadata: {
            refreshToken: pollRes.refreshToken,
            accountId: pollRes.accountId,
          },
        }, "preserve");
      } catch (validationError) {
        const message = validationError instanceof Error ? validationError.message : String(validationError);
        return c.json({ status: "error", error: message });
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

  // Helper: Process Devin authorization code, save credential, poll and update session
  async function processDevinCode(
    sessionId: string,
    code: string,
    verifier: string,
    ownerId: string,
  ): Promise<{ success: boolean; label?: string; error?: string }> {
    const tokenResult = await exchangeDevinCode(code, verifier);
    const initialLabel = tokenResult.email || "Devin";
    const saved = vault.saveCredential(ownerId, {
      ownerId,
      provider: "devin",
      accountLabel: initialLabel,
      credentialType: "api_key",
      secret: tokenResult.token,
      metadata: {
        email: tokenResult.email,
        source: "oauth-pkce",
      },
    });
    const initialReport = await poller.pollCredential(ownerId, saved.id);
    if (initialReport?.error) {
      vault.deleteCredential(ownerId, saved.id);
      const existing = pendingOAuth.get(sessionId);
      pendingOAuth.set(sessionId, { ...existing, provider: "devin", ownerId, status: "error", error: initialReport.error, consumed: true });
      return { success: false, error: initialReport.error };
    }
    const resolvedLabel = initialReport && initialReport.accountLabel && initialReport.accountLabel !== "Devin" && initialReport.accountLabel !== "Default"
      ? initialReport.accountLabel
      : saved.accountLabel;
    if (resolvedLabel !== saved.accountLabel) {
      vault.updateCredentialLabel(ownerId, saved.id, resolvedLabel);
    }
    const existing = pendingOAuth.get(sessionId);
    pendingOAuth.set(sessionId, { ...existing, provider: "devin", ownerId, status: "complete", accountLabel: resolvedLabel, consumed: true });
    return { success: true, label: resolvedLabel };
  }

  // OAuth: Devin - Initiate
  app.post("/api/oauth/devin/initiate", c => {
    try {
      const user = c.get("user");
      const { authUrl, verifier, state, sessionId, isHosted } = initiateDevinAuth();
      pendingOAuth.set(sessionId, {
        provider: "devin",
        ownerId: user.id,
        status: "pending",
        devinVerifier: verifier,
        createdAt: Date.now(),
        consumed: false,
      });

      if (!isHosted) {
        listenForDevinCallback(state)
          .then(async code => {
            const session = pendingOAuth.get(sessionId);
            if (!session || session.consumed || !session.devinVerifier) return;
            const currentVerifier = session.devinVerifier;
            session.consumed = true;
            session.devinVerifier = undefined;
            await processDevinCode(sessionId, code, currentVerifier, user.id);
          })
          .catch(err => {
            pendingOAuth.set(sessionId, {
              provider: "devin",
              ownerId: user.id,
              status: "error",
              error: err instanceof Error ? err.message : "Authorization failed",
            });
          });
      }
      return c.json({
        success: true,
        data: {
          authUrl,
          sessionId,
          redirectUri: getDevinRedirectUri(),
          expiresIn: 600,
        },
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "";
      if (
        msg.includes("DEVIN_OAUTH_REDIRECT_URI is not configured") ||
        msg.includes("Invalid DEVIN_OAUTH_REDIRECT_URI") ||
        msg.includes("DEVIN_OAUTH_REDIRECT_URI must use HTTPS") ||
        msg.includes("DEVIN_OAUTH_REDIRECT_URI path must be exactly") ||
        msg.includes("Unsupported protocol")
      ) {
        return c.json({ success: false, error: msg }, 400);
      }
      return c.json({ success: false, error: "Failed to initiate authorization" }, 500);
    }
  });

  // OAuth: Devin public callback (required when the app runs behind Docker/proxy)
  app.get("/api/oauth/devin/callback", async c => {
    const state = c.req.query("state");
    const code = c.req.query("code");
    const oauthError = c.req.query("error");
    const session = state ? pendingOAuth.get(state) : undefined;
    const successPage = (title: string, message: string, color: string) =>
      c.html(`<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body style="font-family:system-ui,sans-serif;background:#0a0a0b;color:${color};text-align:center;padding:50px"><h2>${title}</h2><p style="color:#a1a1aa">${message}</p><script>setTimeout(()=>window.close(),1500)</script></body></html>`);

    if (!session || session.provider !== "devin") {
      return c.html("Invalid or expired authorization session.", 400);
    }
    if (session.consumed) {
      return c.html("Authorization code already used.", 400);
    }
    if (!session.devinVerifier) {
      return c.html("Invalid or expired authorization session.", 400);
    }
    const OAUTH_SESSION_TTL_MS = 10 * 60 * 1000;
    if (session.createdAt && Date.now() - session.createdAt > OAUTH_SESSION_TTL_MS) {
      pendingOAuth.set(state!, { ...session, status: "error", error: "Authorization session expired", devinVerifier: undefined });
      return successPage("Devin Login Failed", "Authorization session expired. You can close this tab.", "#f43f5e");
    }

    const verifier = session.devinVerifier;
    session.consumed = true;
    session.devinVerifier = undefined;

    if (oauthError) {
      const errorMsg = oauthError === "access_denied" ? "Authorization was denied" : oauthError;
      pendingOAuth.set(state!, { ...session, status: "error", error: errorMsg });
      const displayMsg = oauthError === "access_denied"
        ? "Authorization was denied. You can close this tab."
        : "Authorization failed. You can close this tab.";
      return successPage("Devin Login Failed", displayMsg, "#f43f5e");
    }
    if (!code) {
      pendingOAuth.set(state!, { ...session, status: "error", error: "Authorization code missing" });
      return c.html("Authorization code missing.", 400);
    }

    try {
      const result = await processDevinCode(state!, code, verifier, session.ownerId);
      if (!result.success) {
        return successPage("Devin Login Failed", "Provider validation failed. Please check your dashboard, then close this tab.", "#f43f5e");
      }
      return successPage("Devin Login Successful", "You can close this tab and return to useMeter.", "#10b981");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Authorization failed";
      pendingOAuth.set(state!, { ...session, status: "error", error: msg });
      return successPage("Devin Login Failed", "Authorization failed. You can close this tab.", "#f43f5e");
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

    expireGoogleOAuthSession(session, googleOAuthNow());

    if (session.provider === "devin" && session.status === "pending" && session.createdAt) {
      const OAUTH_SESSION_TTL_MS = 10 * 60 * 1000;
      if (Date.now() - session.createdAt > OAUTH_SESSION_TTL_MS) {
        session.status = "error";
        session.error = "Authorization session expired";
        session.devinVerifier = undefined;
        session.consumed = true;
      }
    }

    return c.json({
      provider: session.provider,
      status: session.status,
      error: session.error,
      accountLabel: session.accountLabel,
    });
  });
  // UI: Dashboard (React client shell)
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
    // Override CSP for dashboard (no CDN needed)
    c.header("Content-Security-Policy", DASHBOARD_CSP);
    return c.html(renderDashboardHtml(enriched, user, assetRevision));
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

export type UsageReportPresentation = {
  accountLabel?: string;
  createdAt?: number;
  accent?: string | null;
  metadata?: Record<string, unknown>;
};

export type PublicUsageReport = Omit<UsageReport, "ownerId" | "raw"> & Omit<UsageReportPresentation, "accountLabel">;

export const PUBLIC_USAGE_METADATA_KEYS = ["email", "login", "username", "accountId", "userId", "planType"] as const;

export function toPublicUsageReport(
  report: UsageReport & { createdAt?: number; accent?: string | null; metadata?: Record<string, unknown> },
  presentation: UsageReportPresentation = {}
): PublicUsageReport {
  const mergedPresentation: UsageReportPresentation = {
    accountLabel: presentation.accountLabel || report.accountLabel,
    createdAt: presentation.createdAt ?? report.createdAt,
    accent: presentation.accent ?? report.accent,
    metadata: presentation.metadata ?? report.metadata,
  };

  let safeMetadata: Record<string, unknown> | undefined;
  if (mergedPresentation.metadata) {
    for (const key of PUBLIC_USAGE_METADATA_KEYS) {
      if (key in mergedPresentation.metadata) {
        (safeMetadata ??= {})[key] = mergedPresentation.metadata[key];
      }
    }
  }

  return {
    provider: report.provider,
    credentialId: report.credentialId,
    accountLabel: mergedPresentation.accountLabel || report.accountLabel,
    fetchedAt: report.fetchedAt,
    limits: report.limits,
    error: report.error ? String(report.error).slice(0, 200) : undefined,
    health: report.health,
    stale: report.stale,
    lastGoodFetchedAt: report.lastGoodFetchedAt,
    source: report.source,
    metadata: safeMetadata,
    accent: mergedPresentation.accent || undefined,
    createdAt: mergedPresentation.createdAt || undefined,
  };
}

function renderDashboardHtml(
  initialReports: (UsageReport & { createdAt?: number; accent?: string | null; metadata?: Record<string, unknown> })[] = [],
  user?: User,
  assetRevision?: string
): string {
  const sanitizedReports = initialReports.map(report => toPublicUsageReport(report, report));

  const safeUser = user ? { id: user.id, email: user.email, role: user.role } : null;
  const bootstrap = JSON.stringify({ reports: sanitizedReports, user: safeUser })
    .replace(/</g, "\\u003c");
  const assetQuery = assetRevision ? `?v=${encodeURIComponent(assetRevision)}` : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>useMeter \u2014 AI Usage Dashboard</title>
  <link rel="stylesheet" href="/assets/app.css${assetQuery}">
</head>
<body>
  <div id="app" data-app="usemeter-dashboard"></div>
  <script id="usemeter-bootstrap" type="application/json">${bootstrap}</script>
  <script type="module" src="/assets/app.js${assetQuery}"></script>
</body>
</html>`;
}

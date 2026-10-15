/**
 * Core security primitives for useMeter:
 * 1. Safe origin parsing & CORS allowlist validation
 * 2. Hardened response security headers & SSR/Tailwind-compatible CSP
 * 3. Bounded in-memory sliding-window RateLimiter with deterministic clock seam
 * 4. Safe client-IP resolver with strict proxy-trust enforcement
 */

// ============================================================================
// 1. Origin Parsing & CORS Allowlist
// ============================================================================

export interface OriginCheckOptions {
  /** Configured allowed origins (comma-separated string, array of strings, or "*") */
  allowedOrigins?: string | string[] | null;
  /** Expected same-origin reference for the incoming request (e.g. "https://app.usemeter.com") */
  requestOrigin?: string | null;
  /** Whether CORS credentials (cookies / authorization headers) are permitted */
  allowCredentials?: boolean;
}

export interface CorsResolverOptions {
  /** Allowed origins specification from env/config */
  allowedOrigins?: string | string[] | null;
  /** Default request origin fallback if context does not specify one */
  defaultRequestOrigin?: string | null;
  /** Whether credentials are enabled (defaults to true for useMeter session cookies) */
  allowCredentials?: boolean;
}

/**
 * Normalizes an origin string:
 * - Trims whitespace
 * - Strips trailing slashes
 * - Lowercases scheme and host
 * - Returns null if malformed
 */
export function normalizeOrigin(origin: string | null | undefined): string | null {
  if (!origin) return null;
  const trimmed = origin.trim();
  if (!trimmed || trimmed === "null") return null;

  try {
    const url = new URL(trimmed);
    // URL.origin returns protocol + '//' + host (including port if non-standard)
    return url.origin.toLowerCase();
  } catch {
    // If not a full URL, strip trailing slash and lowercase
    const cleaned = trimmed.replace(/\/+$/, "").toLowerCase();
    return cleaned.length > 0 ? cleaned : null;
  }
}

/**
 * Parses and normalizes configured allowed origins.
 * - Empty/null/undefined config means same-origin only.
 * - Explicit "*" returns "*" (wildcard).
 * - Delimited string (comma or space) or array returns a list of normalized unique origins.
 */
export function parseAllowedOrigins(
  raw?: string | string[] | null,
  requestOrigin?: string | null
): string[] | "*" {
  if (!raw) {
    const normalizedReq = normalizeOrigin(requestOrigin);
    return normalizedReq ? [normalizedReq] : [];
  }

  if (raw === "*") {
    return "*";
  }

  const rawList = Array.isArray(raw)
    ? raw
    : raw.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);

  if (rawList.includes("*")) {
    return "*";
  }

  const unique = new Set<string>();
  for (const item of rawList) {
    const normalized = normalizeOrigin(item);
    if (normalized) {
      unique.add(normalized);
    }
  }

  if (unique.size === 0 && requestOrigin) {
    const normalizedReq = normalizeOrigin(requestOrigin);
    if (normalizedReq) unique.add(normalizedReq);
  }

  return Array.from(unique);
}

/**
 * Evaluates whether an incoming `Origin` is permitted:
 * - Empty config enforces strict same-origin (matches `requestOrigin`).
 * - Explicit `*` is STRICTLY REJECTED if `allowCredentials` is true.
 * - Configured allowlist matches exact normalized origin (no partial/subdomain hijacking).
 */
export function isOriginAllowed(
  origin: string | null | undefined,
  options: OriginCheckOptions = {}
): boolean {
  const normalizedIncoming = normalizeOrigin(origin);
  if (!normalizedIncoming) {
    return false;
  }

  const { allowedOrigins, requestOrigin, allowCredentials = true } = options;
  const parsed = parseAllowedOrigins(allowedOrigins, requestOrigin);

  // 1. Wildcard handling
  if (parsed === "*") {
    // RFC 6454 & CORS specification: Access-Control-Allow-Origin: * MUST NOT be used with credentials
    if (allowCredentials) {
      return false;
    }
    return true;
  }

  // 2. Allowlist checks
  if (parsed.includes(normalizedIncoming)) {
    return true;
  }

  // 3. Fallback same-origin check if requestOrigin is provided
  if (requestOrigin) {
    const normalizedReq = normalizeOrigin(requestOrigin);
    if (normalizedReq && normalizedIncoming === normalizedReq) {
      return true;
    }
  }

  return false;
}

/**
 * Creates a CORS origin resolver function compatible with Hono and standard HTTP frameworks.
 * Returns the validated origin to reflect, "*" if non-credentialed wildcard is active, or null if rejected.
 */
export function createCorsOriginResolver(
  options: CorsResolverOptions = {}
): (origin: string, context?: { req?: { url?: string; header?: (name: string) => string | undefined } }) => string | null {
  const { allowedOrigins, defaultRequestOrigin, allowCredentials = true } = options;

  return (incomingOrigin: string, context?: { req?: { url?: string; header?: (name: string) => string | undefined } }) => {
    let reqOrigin = defaultRequestOrigin;
    if (context?.req?.url) {
      try {
        reqOrigin = new URL(context.req.url).origin;
      } catch {
        // use default fallback
      }
    }

    const allowed = isOriginAllowed(incomingOrigin, {
      allowedOrigins,
      requestOrigin: reqOrigin,
      allowCredentials,
    });

    if (!allowed) {
      return null;
    }

    if (allowedOrigins === "*" && !allowCredentials) {
      return "*";
    }

    // Return the specific normalized incoming origin to reflect
    return normalizeOrigin(incomingOrigin);
  };
}

// ============================================================================
// 2. Security Headers & CSP
// ============================================================================

/**
 * Documented minimal Content-Security-Policy.
 * Compatible with useMeter's current inline SSR scripts, inline theme styles, and Tailwind CDN.
 * Does not falsely claim nonces or hashes that are not injected by the template engine.
 */
export const MINIMAL_SSR_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

/**
 * Dashboard CSP for locally-built React client — no external CDN needed.
 */
export const DASHBOARD_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

export interface SecurityHeadersOptions {
  /** Custom CSP policy string, or null to omit */
  contentSecurityPolicy?: string | null;
  /** Custom Permissions-Policy string, or null to omit */
  permissionsPolicy?: string | null;
  /** Whether to enforce HSTS header (overrides secure parameter if specified) */
  hsts?: boolean;
  /** HSTS max-age in seconds (default: 31536000 = 1 year) */
  hstsMaxAge?: number;
  /** Override the default Referrer-Policy response header. */
  referrerPolicy?: string;
}

/**
 * Returns standard production-grade HTTP security headers.
 * HSTS is included ONLY when `secure` is true.
 */
export function getSecurityHeaders(
  secure: boolean,
  options: SecurityHeadersOptions = {}
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": options.referrerPolicy ?? "strict-origin-when-cross-origin",
  };

  const csp = options.contentSecurityPolicy !== undefined ? options.contentSecurityPolicy : MINIMAL_SSR_CSP;
  if (csp) {
    headers["Content-Security-Policy"] = csp;
  }

  const permissions =
    options.permissionsPolicy !== undefined
      ? options.permissionsPolicy
      : "camera=(), microphone=(), geolocation=(), payment=()";
  if (permissions) {
    headers["Permissions-Policy"] = permissions;
  }

  const shouldApplyHsts = options.hsts !== undefined ? options.hsts : secure;
  if (shouldApplyHsts) {
    const maxAge = options.hstsMaxAge ?? 31_536_000;
    headers["Strict-Transport-Security"] = `max-age=${maxAge}; includeSubDomains`;
  }

  return headers;
}

/**
 * Injects security headers into an existing Headers instance or plain Record.
 */
export function applySecurityHeaders<T extends Headers | Record<string, string>>(
  target: T,
  secure: boolean,
  options?: SecurityHeadersOptions
): T {
  const secHeaders = getSecurityHeaders(secure, options);

  if (typeof (target as Headers).set === "function") {
    const h = target as Headers;
    for (const [key, value] of Object.entries(secHeaders)) {
      h.set(key, value);
    }
    return target;
  }

  const rec = target as Record<string, string>;
  for (const [key, value] of Object.entries(secHeaders)) {
    rec[key] = value;
  }
  return target;
}

// ============================================================================
// 3. Bounded In-Memory RateLimiter
// ============================================================================

export interface RateLimitPolicy {
  /** Maximum number of allowed requests in the window */
  max: number;
  /** Rolling window duration in milliseconds */
  windowMs: number;
}

export interface RateLimitResult {
  /** Whether the request is permitted */
  allowed: boolean;
  /** Number of remaining requests in the current window */
  remaining: number;
  /** Milliseconds until the rate limit window resets */
  resetMs: number;
  /** Seconds to wait before retrying (defined only when allowed === false) */
  retryAfterSec?: number;
  /** Total limit allowed by the policy */
  total: number;
}

export interface RateLimiterOptions {
  /** Maximum number of unique keys tracked before evicting (default: 10,000) */
  maxKeys?: number;
  /** Deterministic clock injection seam (defaults to Date.now) */
  now?: () => number;
}

interface RateLimitEntry {
  timestamps: number[];
  lastAccessed: number;
}

/**
 * Standard endpoint policies specified for useMeter:
 * - auth: 5/min/IP
 * - registration: 5/min/IP
 * - manualPoll: 1/30s/user+credential
 * - oauthDevicePoll: 30/min/user+flow
 * - passwordChange: 3/15m/user+IP
 * - passwordResetRequest: 5/hour/IP and address
 * - passwordResetConfirm: 5/15m/IP
 * - accountDelete: 3/15m/user+IP
 */
export const RATE_LIMIT_POLICIES = {
  auth: { max: 5, windowMs: 60_000 },
  registration: { max: 5, windowMs: 60_000 },
  manualPoll: { max: 1, windowMs: 30_000 },
  oauthDevicePoll: { max: 30, windowMs: 60_000 },
  passwordChange: { max: 3, windowMs: 15 * 60_000 },
  passwordResetRequest: { max: 5, windowMs: 60 * 60_000 },
  passwordResetConfirm: { max: 5, windowMs: 15 * 60_000 },
  accountDelete: { max: 3, windowMs: 15 * 60_000 },
} as const satisfies Record<string, RateLimitPolicy>;

export class RateLimiter {
  private readonly entries = new Map<string, RateLimitEntry>();
  private readonly maxKeys: number;
  private readonly now: () => number;

  constructor(options: RateLimiterOptions = {}) {
    this.maxKeys = options.maxKeys ?? 10_000;
    this.now = options.now ?? (() => Date.now());
  }

  /**
   * Checks and consumes a request under the given key and policy.
   * Uses an in-memory sliding window algorithm.
   */
  public check(key: string, policy: RateLimitPolicy): RateLimitResult {
    const currentTime = this.now();
    const windowStart = currentTime - policy.windowMs;

    let entry = this.entries.get(key);
    if (!entry) {
      this.ensureCapacity(currentTime);
      entry = { timestamps: [], lastAccessed: currentTime };
      this.entries.set(key, entry);
    } else {
      // Refresh access order (LRU behavior)
      this.entries.delete(key);
      entry.lastAccessed = currentTime;
      this.entries.set(key, entry);
    }

    // Filter out timestamps outside the sliding window
    entry.timestamps = entry.timestamps.filter(ts => ts > windowStart);

    if (entry.timestamps.length < policy.max) {
      entry.timestamps.push(currentTime);
      const remaining = policy.max - entry.timestamps.length;
      const oldest = entry.timestamps[0] ?? currentTime;
      const resetMs = Math.max(0, oldest + policy.windowMs - currentTime);

      return {
        allowed: true,
        remaining,
        resetMs,
        total: policy.max,
      };
    }

    // Rate limit exceeded
    const oldest = entry.timestamps[0] ?? currentTime;
    const resetMs = Math.max(0, oldest + policy.windowMs - currentTime);
    const retryAfterSec = Math.max(1, Math.ceil(resetMs / 1000));

    return {
      allowed: false,
      remaining: 0,
      resetMs,
      retryAfterSec,
      total: policy.max,
    };
  }

  /**
   * Resets rate limit records for a single key, or clears all records if key is omitted.
   */
  public reset(key?: string): void {
    if (key !== undefined) {
      this.entries.delete(key);
    } else {
      this.entries.clear();
    }
  }

  /**
   * Returns current number of tracked keys.
   */
  public size(): number {
    return this.entries.size;
  }

  /**
   * Prunes expired entries based on provided window or maximum age.
   */
  public prune(maxAgeMs = 120_000): number {
    const threshold = this.now() - maxAgeMs;
    let pruned = 0;
    for (const [k, entry] of this.entries.entries()) {
      if (entry.lastAccessed < threshold) {
        this.entries.delete(k);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Enforces bounded memory capacity by evicting stale or LRU entries.
   */
  private ensureCapacity(currentTime: number): void {
    if (this.entries.size < this.maxKeys) {
      return;
    }

    // 1. Pass: clean up entries whose last access is older than 5 minutes
    const staleThreshold = currentTime - 300_000;
    for (const [k, entry] of this.entries.entries()) {
      if (entry.lastAccessed < staleThreshold) {
        this.entries.delete(k);
      }
      if (this.entries.size < this.maxKeys) {
        return;
      }
    }

    // 2. Pass: if still full, evict oldest accessed keys (first entries in Map iteration)
    const excess = this.entries.size - this.maxKeys + 1;
    let count = 0;
    for (const k of this.entries.keys()) {
      this.entries.delete(k);
      count++;
      if (count >= excess) {
        break;
      }
    }
  }
}

// ============================================================================
// 4. Safe Client-IP Resolver
// ============================================================================

export interface ClientIpOptions {
  /** Explicitly trust reverse-proxy headers like X-Forwarded-For */
  trustProxy?: boolean;
  /** Direct remote IP address if provided by runtime/socket */
  remoteAddress?: string;
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

function sanitizeIp(raw: string): string | null {
  let cleaned = raw.trim();
  // Strip bracketed IPv6 with port: [2001:db8::1]:8080 -> 2001:db8::1
  if (cleaned.startsWith("[") && cleaned.includes("]")) {
    const closeBracket = cleaned.indexOf("]");
    cleaned = cleaned.slice(1, closeBracket);
  } else if (cleaned.includes(".") && cleaned.includes(":")) {
    // Strip port from IPv4: 1.2.3.4:8080 -> 1.2.3.4
    const parts = cleaned.split(":");
    if (parts.length === 2 && IPV4_REGEX.test(parts[0])) {
      cleaned = parts[0];
    }
  }

  if (IPV4_REGEX.test(cleaned)) {
    return cleaned;
  }

  if (cleaned.includes(":")) {
    try {
      const u = new URL(`http://[${cleaned}]`);
      if (u.hostname === `[${cleaned.toLowerCase()}]`) {
        return cleaned.toLowerCase();
      }
    } catch {
      // Malformed IPv6
    }
  }

  return null;
}

function getHeaderValue(
  headers: Headers | Record<string, string | string[] | undefined> | undefined,
  name: string
): string | null {
  if (!headers) return null;
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(name);
  }
  const rec = headers as Record<string, string | string[] | undefined>;
  const val = rec[name] ?? rec[name.toLowerCase()];
  if (Array.isArray(val)) return val[0] ?? null;
  return typeof val === "string" ? val : null;
}

/**
 * Resolves the client IP address safely:
 * - If `trustProxy` is false (default), X-Forwarded-For is strictly IGNORED to prevent spoofing.
 * - If `trustProxy` is true (or env TRUST_PROXY="true"), uses leftmost valid client IP from X-Forwarded-For.
 * - Falls back to remoteAddress or "127.0.0.1".
 */
export function resolveClientIp(
  input?: Request | Headers | Record<string, string | string[] | undefined> | { headers?: Headers | Record<string, string | string[] | undefined>; remoteAddress?: string } | null,
  options: ClientIpOptions = {}
): string {
  const trustProxy =
    options.trustProxy !== undefined
      ? options.trustProxy
      : process.env["TRUST_PROXY"] === "true" || process.env["TRUST_PROXY"] === "1";

  let headers: Headers | Record<string, string | string[] | undefined> | undefined;
  let remoteAddress = options.remoteAddress;

  if (input) {
    if ("headers" in input && input.headers) {
      headers = input.headers as Headers;
      if ("remoteAddress" in input && typeof input.remoteAddress === "string") {
        remoteAddress = remoteAddress ?? input.remoteAddress;
      }
    } else if (typeof (input as Headers).get === "function" || typeof input === "object") {
      headers = input as Headers;
    }
  }

  // 1. If reverse proxy is trusted, inspect forwarding headers
  if (trustProxy && headers) {
    const xff = getHeaderValue(headers, "x-forwarded-for");
    if (xff) {
      const parts = xff.split(",");
      for (const rawPart of parts) {
        const sanitized = sanitizeIp(rawPart);
        if (sanitized) {
          return sanitized;
        }
      }
    }

    const xRealIp = getHeaderValue(headers, "x-real-ip");
    if (xRealIp) {
      const sanitized = sanitizeIp(xRealIp);
      if (sanitized) {
        return sanitized;
      }
    }
  }

  // 2. Fall back to remote address if available
  if (remoteAddress) {
    const sanitized = sanitizeIp(remoteAddress);
    if (sanitized) {
      return sanitized;
    }
  }

  return "127.0.0.1";
}

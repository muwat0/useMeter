import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { PollerEngine } from "../src/core/poller/poller";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { createServer } from "../src/server/app";
import type { UsageReport } from "../src/types";
interface BootstrapReport extends UsageReport {
  metadata?: Record<string, unknown>;
}

function extractBootstrap(html: string): { reports: BootstrapReport[]; user: { id: string; email: string; role: string } } {
  const match = html.match(/<script id="usemeter-bootstrap"[^>]*>([\s\S]*?)<\/script>/);
  if (!match?.[1]) throw new Error("missing dashboard bootstrap");
  return JSON.parse(match[1]) as { reports: BootstrapReport[]; user: { id: string; email: string; role: string } };
}

describe("React dashboard shell", () => {
  it("serves built assets with immutable caching and HEAD support", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry());
    const app = createServer(vault, poller);
    try {
      const css = await app.request("/assets/app.css");
      expect(css.status).toBe(200);
      expect(css.headers.get("Content-Type")).toContain("text/css");
      expect(css.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
      expect((await css.text()).length).toBeGreaterThan(100);

      const jsHead = await app.request("/assets/app.js", { method: "HEAD" });
      expect(jsHead.status).toBe(200);
      expect(jsHead.headers.get("Content-Type")).toContain("application/javascript");
      expect(jsHead.headers.get("Content-Length")).toBeTruthy();
      expect(await jsHead.text()).toBe("");

      const traversal = await app.request("/assets/%2e%2e%2fsrc%2fserver%2fapp.ts");
      expect(traversal.status).toBe(403);
    } finally {
      vault.close();
    }
  });

  it("keeps dashboard CSP local-only while secondary SSR pages retain CDN compatibility", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry());
    const app = createServer(vault, poller);
    try {
      const login = await app.request("/login");
      const loginCsp = login.headers.get("Content-Security-Policy") || "";
      expect(loginCsp).toContain("https://cdn.tailwindcss.com");

      const register = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "shell-csp@example.com", password: "Password12345678!" }),
      });
      const cookie = register.headers.get("Set-Cookie")!.split(";")[0]!;
      const dashboard = await app.request("/", { headers: { Cookie: cookie } });
      const dashboardCsp = dashboard.headers.get("Content-Security-Policy") || "";
      expect(dashboardCsp).toContain("script-src 'self'");
      expect(dashboardCsp).not.toContain("cdn.tailwindcss.com");
    } finally {
      vault.close();
    }
  });

  it("sanitizes bootstrap metadata and excludes raw report payloads", async () => {
    const vault = new StorageVault(":memory:");
    const poller = new PollerEngine(vault, createDefaultRegistry());
    const app = createServer(vault, poller);
    try {
      const register = await app.request("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "bootstrap@example.com", password: "Password12345678!" }),
      });
      const cookie = register.headers.get("Set-Cookie")!.split(";")[0]!;
      const user = vault.getUserByEmail("bootstrap@example.com")!;
      const credential = vault.saveCredential(user.id, {
        provider: "openrouter",
        accountLabel: "Bootstrap Account",
        credentialType: "api_key",
        secret: "sk-live-secret-must-not-render",
        metadata: {
          email: "provider@example.com",
          planType: "pro",
          refreshToken: "refresh-secret-must-not-render",
          rawCookie: "cookie-secret-must-not-render",
        },
      });
      vault.saveUsageSnapshot(user.id, {
        ownerId: user.id,
        provider: "openrouter",
        credentialId: credential.id,
        accountLabel: credential.accountLabel,
        fetchedAt: Date.now(),
        limits: [{
          id: "balance_usd",
          label: "Balance",
          amount: { unit: "usd", remaining: 4.25 },
          status: "ok",
        }],
        raw: { accessToken: "raw-token-must-not-render" },
      });

      const response = await app.request("/", { headers: { Cookie: cookie } });
      expect(response.status).toBe(200);
      const html = await response.text();
      const bootstrap = extractBootstrap(html);
      expect(bootstrap.user.email).toBe("bootstrap@example.com");
      expect(bootstrap.reports[0]?.metadata).toEqual({ email: "provider@example.com", planType: "pro" });
      expect(html).not.toContain("sk-live-secret-must-not-render");
      expect(html).not.toContain("refresh-secret-must-not-render");
      expect(html).not.toContain("cookie-secret-must-not-render");
      expect(html).not.toContain("raw-token-must-not-render");
      expect(html).not.toContain("accessToken");
    } finally {
      vault.close();
    }
  });
});

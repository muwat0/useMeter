import { afterEach, describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { AuthService } from "../src/core/auth/auth";
import { PollerEngine } from "../src/core/poller/poller";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { createServer } from "../src/server/app";

const LEGAL_ROUTES = [
  { path: "/privacy", titleTr: "Gizlilik", titleEn: "Privacy" },
  { path: "/terms", titleTr: "Kullanım Koşulları", titleEn: "Terms of Use" },
  { path: "/security", titleTr: "Güvenlik", titleEn: "Security" },
  { path: "/support", titleTr: "Destek", titleEn: "Support" },
] as const;

const contexts: Array<{ vault: StorageVault }> = [];

afterEach(() => {
  for (const context of contexts.splice(0)) context.vault.close();
});

function createTestApp() {
  const vault = new StorageVault(":memory:");
  contexts.push({ vault });
  const registry = createDefaultRegistry();
  const poller = new PollerEngine(vault, registry, { minProviderIntervalMs: 0 });
  return createServer(vault, poller, registry, new AuthService(vault));
}

describe("public legal and support pages", () => {
  it("serves every page without authentication and applies strict security headers", async () => {
    const app = createTestApp();

    for (const route of LEGAL_ROUTES) {
      const response = await app.request(route.path);
      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toContain("text/html");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(response.headers.get("X-Frame-Options")).toBe("DENY");
      expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
      expect(response.headers.get("Permissions-Policy")).toContain("camera=()");

      const csp = response.headers.get("Content-Security-Policy");
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("script-src 'none'");
      expect(csp).toContain("style-src 'unsafe-inline'");
      expect(csp).toContain("img-src 'none'");
      expect(csp).toContain("font-src 'none'");
      expect(csp).toContain("connect-src 'none'");
      expect(csp).toContain("object-src 'none'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).not.toMatch(/https?:\/\//i);

      const html = await response.text();
      expect(html).toContain(route.titleTr);
      expect(html).not.toMatch(/<(?:script|link|img|iframe|source)\b[^>]*\b(?:src|href)\s*=\s*["'](?:https?:)?\/\//i);
      expect(html).not.toMatch(/<script\b/i);
      expect(html).toContain("id=\"theme-toggle\"");
      expect(html).toContain("?lang=tr");
      expect(html).toContain("?lang=en");
    }
  });

  it("renders the requested language for every page", async () => {
    const app = createTestApp();

    for (const route of LEGAL_ROUTES) {
      const turkish = await app.request(route.path);
      const english = await app.request(`${route.path}?lang=en`);

      expect(turkish.status).toBe(200);
      expect((await turkish.text()).match(/<html lang="tr">/)).toBeTruthy();
      expect(english.status).toBe(200);
      const englishHtml = await english.text();
      expect(englishHtml).toContain('<html lang="en">');
      expect(englishHtml).toContain(route.titleEn);
    }
  });

  it("discloses storage, retention, billing, security, and support boundaries", async () => {
    const app = createTestApp();
    const privacy = await (await app.request("/privacy")).text();
    const terms = await (await app.request("/terms")).text();
    const security = await (await app.request("/security")).text();
    const support = await (await app.request("/support")).text();

    expect(privacy).toContain("AES-256-GCM");
    expect(privacy).toContain("Argon2id");
    expect(privacy).toContain("7 gün");
    expect(privacy).toContain("SNAPSHOT_RETENTION_DAYS");
    expect(privacy).toContain("ON DELETE CASCADE");
    expect(privacy).toContain("satmaz");
    expect(privacy).toContain("anlık görüntüleri");

    expect(terms).toContain("olduğu gibi");
    expect(terms).toContain("faturalandırma kaydı değildir");
    expect(terms).toContain("USAGE_MASTER_KEY");

    expect(security).toContain("USAGE_MASTER_KEY");
    expect(security).toContain("AES-256-GCM");
    expect(security).toContain("Argon2id");
    expect(security).toContain("security@muwat.org");
    expect(security).toContain("murat@muwat.org");

    expect(support).toContain("https://github.com/muwat0/useMeter/issues");
    expect(support).toContain("murat@muwat.org");
  });
});

import { afterEach, describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { AuthService } from "../src/core/auth/auth";
import { PollerEngine } from "../src/core/poller/poller";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { createServer } from "../src/server/app";
import { APP_VERSION } from "../src/version";
import { CHANGELOG_RELEASES } from "../src/server/changelog";

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

describe("public changelog page", () => {
  it("serves /changelog without authentication and applies strict security headers", async () => {
    const app = createTestApp();
    const response = await app.request("/changelog");

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("text/html");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");

    const csp = response.headers.get("Content-Security-Policy");
    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'sha256-");
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
    expect(csp).toContain("style-src 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("renders the requested language for changelog (TR default and EN toggle)", async () => {
    const app = createTestApp();

    const turkishRes = await app.request("/changelog");
    expect(turkishRes.status).toBe(200);
    const turkishHtml = await turkishRes.text();
    expect(turkishHtml).toContain('<html lang="tr">');
    expect(turkishHtml).toContain("Sürüm Notları");
    expect(turkishHtml).toContain("En Güncel Sürüm");
    expect(turkishHtml).toContain("Eklendi");
    expect(turkishHtml).toContain("Güvenlik");

    const englishRes = await app.request("/changelog?lang=en");
    expect(englishRes.status).toBe(200);
    const englishHtml = await englishRes.text();
    expect(englishHtml).toContain('<html lang="en">');
    expect(englishHtml).toContain("Release Notes");
    expect(englishHtml).toContain("Latest Release");
    expect(englishHtml).toContain("Added");
    expect(englishHtml).toContain("Security");
  });

  it("renders the active version and Zen-style release cards", async () => {
    const app = createTestApp();
    const response = await app.request("/changelog");
    const html = await response.text();

    expect(html).toContain(`v${APP_VERSION}`);
    expect(html).toContain("release-card");
    expect(html).toContain("release-latest");
    expect(html).toContain("badge-added");
    expect(html).toContain("badge-security");
    expect(html).toContain("badge-fixed");
    expect(html).toContain("badge-ops");

    for (const rel of CHANGELOG_RELEASES) {
      expect(html).toContain(rel.version);
    }
  });

  it("includes navigation back to dashboard and legal links", async () => {
    const app = createTestApp();
    const response = await app.request("/changelog");
    const html = await response.text();

    expect(html).toContain('href="/"');
    expect(html).toContain('href="/privacy?lang=tr"');
    expect(html).toContain('href="/terms?lang=tr"');
    expect(html).toContain('href="/security?lang=tr"');
    expect(html).toContain('href="/support?lang=tr"');
  });
});

import { describe, expect, it } from "bun:test";
import { StorageVault } from "../src/core/storage/vault";
import { PollerEngine } from "../src/core/poller/poller";
import { createDefaultRegistry } from "../src/core/providers/registry";
import { createServer } from "../src/server/app";

function context() {
  const vault = new StorageVault(":memory:");
  const poller = new PollerEngine(vault, createDefaultRegistry());
  const app = createServer(vault, poller);
  return { vault, app };
}

async function register(app: ReturnType<typeof createServer>) {
  const response = await app.request("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "google-callback@example.com", password: "Password12345678!" }),
  });
  return response.headers.get("Set-Cookie")!.split(";")[0]!;
}

describe("Google public OAuth callback", () => {
  it("is reachable without an application session and rejects unknown state safely", async () => {
    const { vault, app } = context();
    try {
      const response = await app.request("/api/oauth/google/callback?state=unknown&code=redacted");
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("Invalid or expired authorization session");
    } finally {
      vault.close();
    }
  });

  it("returns a public callback URL from Google initiation", async () => {
    const { vault, app } = context();
    try {
      const cookie = await register(app);
      const response = await app.request("/api/oauth/google/initiate", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { success: boolean; data?: { authUrl: string; sessionId: string; redirectUri?: string } };
      expect(body.success).toBe(true);
      expect(body.data?.authUrl).toContain(encodeURIComponent(body.data?.redirectUri || ""));
      expect(body.data?.sessionId).toBeTruthy();
    } finally {
      vault.close();
    }
  });
});

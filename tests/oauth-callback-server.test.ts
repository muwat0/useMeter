import { describe, expect, it } from "bun:test";
import { listenForOAuthCallback, stopCallbackServer } from "../src/core/oauth/callback-server";

function freeLoopbackPort(): number {
  const probe = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch: () => new Response("probe"),
  });
  const port = probe.port;
  probe.stop(true);
  if (port === undefined) throw new Error("Synthetic loopback server did not receive an ephemeral port");
  return port;
}


describe("OAuth callback listener ownership", () => {
  it("does not let an old listener's delayed close or abort affect its replacement", async () => {
    const port = freeLoopbackPort();
    const oldController = new AbortController();
    try {
      const oldListener = listenForOAuthCallback({
        port,
        pathname: "/callback",
        expectedState: "old-state",
        providerName: "synthetic-old",
        timeoutMs: 5_000,
        signal: oldController.signal,
      });
      const oldResponse = await fetch(`http://127.0.0.1:${port}/callback?code=old-code&state=old-state`);
      expect(oldResponse.status).toBe(200);
      expect(await oldListener).toBe("old-code");

      const replacementController = new AbortController();
      const replacement = listenForOAuthCallback({
        port,
        pathname: "/callback",
        expectedState: "new-state",
        providerName: "synthetic-new",
        timeoutMs: 5_000,
        signal: replacementController.signal,
      });
      // Exercise the platform's real 500 ms delayed-close timer while a new listener owns the port.
      oldController.abort();
      const closeDelay = Promise.withResolvers<void>();
      setTimeout(closeDelay.resolve, 650);
      await closeDelay.promise;

      const replacementResponse = await fetch(`http://127.0.0.1:${port}/callback?code=new-code&state=new-state`);
      expect(replacementResponse.status).toBe(200);
      expect(await replacement).toBe("new-code");
    } finally {
      stopCallbackServer(port);
    }
  });

  it("closes the listener and rejects its wait when its own session is aborted", async () => {
    const port = freeLoopbackPort();
    const controller = new AbortController();
    const listener = listenForOAuthCallback({
      port,
      pathname: "/callback",
      providerName: "synthetic-abort",
      timeoutMs: 5_000,
      signal: controller.signal,
    });
    try {
      controller.abort();
      await expect(listener).rejects.toMatchObject({ name: "AbortError" });
      await expect(fetch(`http://127.0.0.1:${port}/callback?code=late-code`)).rejects.toThrow();
    } finally {
      stopCallbackServer(port);
    }
  });
});

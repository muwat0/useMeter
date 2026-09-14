import type { Server } from "bun";

const activeServers = new Map<number, Server<unknown>>();

/**
 * Stop any running callback server on the specified port.
 */
export function stopCallbackServer(port: number): void {
  const existing = activeServers.get(port);
  if (existing) {
    try {
      existing.stop(true);
    } catch {}
    activeServers.delete(port);
  }
}

export interface CallbackOptions {
  port: number;
  pathname: string;
  expectedState?: string;
  providerName: string;
  timeoutMs?: number;
}

/**
 * Spins up a temporary HTTP server on 127.0.0.1:port to catch an OAuth redirect.
 * Resolves with the authorization code upon receipt.
 */
export async function listenForOAuthCallback(options: CallbackOptions): Promise<string> {
  const { port, pathname, expectedState, providerName, timeoutMs = 120_000 } = options;

  stopCallbackServer(port);

  const { promise, resolve, reject } = Promise.withResolvers<string>();

  let timer: ReturnType<typeof setTimeout> | undefined;
  let server: Server<unknown>;

  try {
    server = Bun.serve({
      port,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === pathname) {
          const code = url.searchParams.get("code");
          const state = url.searchParams.get("state");
          const error = url.searchParams.get("error");
          const errorDesc = url.searchParams.get("error_description");

          if (error) {
            reject(new Error(errorDesc || error));
            setTimeout(() => {
              stopCallbackServer(port);
            }, 500);
            return new Response(
              `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title></head><body style="font-family:sans-serif;background:#0a0a0b;color:#f43f5e;text-align:center;padding:50px;"><h2>Giriş Başarısız / Authentication Failed</h2><p style="color:#a1a1aa;">${errorDesc || error}</p></body></html>`,
              { headers: { "Content-Type": "text/html; charset=utf-8" } }
            );
          }

          if (expectedState && state !== expectedState) {
            return new Response("Geçersiz state parametresi (Invalid state).", { status: 400 });
          }

          if (!code) {
            return new Response("Yetkilendirme kodu bulunamadı (No code).", { status: 400 });
          }

          resolve(code);
          setTimeout(() => {
            stopCallbackServer(port);
          }, 500);

          return new Response(
            `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${providerName} Login</title></head><body style="font-family:sans-serif;background:#0a0a0b;color:#10b981;text-align:center;padding:50px;"><h2>${providerName} Girişi Başarılı!</h2><p style="color:#a1a1aa;">Bu sekmeyi kapatıp useMeter paneline dönebilirsiniz.</p><script>setTimeout(() => window.close(), 1500);</script></body></html>`,
            { headers: { "Content-Type": "text/html; charset=utf-8" } }
          );
        }
        return new Response("Not found", { status: 404 });
      },
    });

    activeServers.set(port, server);
  } catch (err) {
    reject(err);
    return promise;
  }

  timer = setTimeout(() => {
    stopCallbackServer(port);
    reject(new Error(`Zaman aşımı: ${providerName} giriş isteği zamanında tamamlanmadı.`));
  }, timeoutMs);

  return promise.finally(() => {
    clearTimeout(timer);
  });
}

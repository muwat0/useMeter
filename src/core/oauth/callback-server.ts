import type { Server } from "bun";

interface ActiveCallbackServer {
  server: Server<unknown>;
  stop: () => void;
}

const activeServers = new Map<number, ActiveCallbackServer>();

/**
 * Stop the current callback server on the specified port.
 */
export function stopCallbackServer(port: number): void {
  activeServers.get(port)?.stop();
}

export interface CallbackOptions {
  port: number;
  pathname: string;
  expectedState?: string;
  providerName: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/**
 * Spins up a temporary HTTP server on 127.0.0.1:port to catch an OAuth redirect.
 * Resolves with the authorization code upon receipt.
 */
export async function listenForOAuthCallback(options: CallbackOptions): Promise<string> {
  const { port, pathname, expectedState, providerName, timeoutMs = 120_000, signal } = options;
  const { promise, resolve, reject } = Promise.withResolvers<string>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let closeTimer: ReturnType<typeof setTimeout> | undefined;
  let settled = false;

  const finish = (error?: Error, code?: string) => {
    if (settled) return;
    settled = true;
    if (error) reject(error);
    else resolve(code!);
  };
  const abortError = () => {
    const error = new Error("OAuth callback listener aborted");
    error.name = "AbortError";
    return error;
  };

  if (signal?.aborted) {
    finish(abortError());
    return promise;
  }

  stopCallbackServer(port);

  let active: ActiveCallbackServer | undefined;
  let onAbort = () => {};
  const closeCapturedServer = () => {
    if (!active) return;
    if (activeServers.get(port) === active) activeServers.delete(port);
    try {
      active.server.stop(true);
    } catch {}
    if (signal) signal.removeEventListener("abort", onAbort);
  };
  const scheduleClose = () => {
    closeTimer = setTimeout(closeCapturedServer, 500);
    closeTimer.unref?.();
  };
  onAbort = () => {
    closeCapturedServer();
    finish(abortError());
  };

  try {
    const server = Bun.serve({
      port,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname !== pathname) return new Response("Not found", { status: 404 });

        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const error = url.searchParams.get("error");
        const errorDesc = url.searchParams.get("error_description");
        if (error) {
          finish(new Error(errorDesc || error));
          scheduleClose();
          return new Response(
            `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title></head><body style="font-family:sans-serif;background:#0a0a0b;color:#f43f5e;text-align:center;padding:50px;"><h2>Giriş Başarısız / Authentication Failed</h2><p style="color:#a1a1aa;">${errorDesc || error}</p></body></html>`,
            { headers: { "Content-Type": "text/html; charset=utf-8" } },
          );
        }

        if (expectedState && state !== expectedState) {
          return new Response("Geçersiz state parametresi (Invalid state).", { status: 400 });
        }
        if (!code) {
          return new Response("Yetkilendirme kodu bulunamadı (No code).", { status: 400 });
        }

        finish(undefined, code);
        scheduleClose();
        return new Response(
          `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${providerName} Login</title></head><body style="font-family:sans-serif;background:#0a0a0b;color:#10b981;text-align:center;padding:50px;"><h2>${providerName} Girişi Başarılı!</h2><p style="color:#a1a1aa;">Bu sekmeyi kapatıp useMeter paneline dönebilirsiniz.</p><script>setTimeout(() => window.close(), 1500);</script></body></html>`,
          { headers: { "Content-Type": "text/html; charset=utf-8" } },
        );
      },
    });
    active = {
      server,
      stop() {
        closeCapturedServer();
        finish(new Error(`Callback listener on port ${port} was stopped`));
      },
    };
    activeServers.set(port, active);
  } catch (err) {
    finish(err instanceof Error ? err : new Error(String(err)));
    return promise;
  }

  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();
  timer = setTimeout(() => {
    closeCapturedServer();
    finish(new Error(`Zaman aşımı: ${providerName} giriş isteği zamanında tamamlanmadı.`));
  }, timeoutMs);
  timer.unref?.();

  return promise.finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

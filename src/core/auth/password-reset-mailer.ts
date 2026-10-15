import * as net from "node:net";

export interface PasswordResetMail {
  recipient: string;
  token: string;
}

export interface PasswordResetMailer {
  send(mail: PasswordResetMail, signal: AbortSignal): Promise<void>;
}

const MAX_RESPONSE_BYTES = 512;
const TOKEN_HEX_REGEX = /^[0-9a-f]{64}$/;
const EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/**
 * Creates a PasswordResetMailer connected to a local Unix domain socket bridge.
 * Throws synchronously if socketPath is not a non-empty string.
 */
export function createUnixPasswordResetMailer(socketPath: string): PasswordResetMailer {
  if (typeof socketPath !== "string" || socketPath.trim() === "") {
    throw new TypeError("socketPath must be a non-empty string");
  }
  const normalizedSocketPath = socketPath.trim();

  return {
    async send(mail: PasswordResetMail, signal: AbortSignal): Promise<void> {
      if (!signal || typeof signal.aborted !== "boolean") {
        throw new TypeError("signal must be an AbortSignal");
      }

      if (!mail || typeof mail !== "object") {
        throw new TypeError("PasswordResetMail must be an object with recipient and token");
      }

      if (typeof mail.recipient !== "string" || mail.recipient === "") {
        throw new Error("Invalid password reset recipient");
      }
      // Check control characters, whitespace, leading dash BEFORE any trimming
      if (
        /[\x00-\x20\x7f-\x9f\r\n]/.test(mail.recipient) ||
        mail.recipient.startsWith("-") ||
        mail.recipient.length > 254 ||
        !EMAIL_REGEX.test(mail.recipient)
      ) {
        throw new Error("Invalid password reset recipient format");
      }

      // Exact 64 lowercase hexadecimal characters; no trimming, no case-folding
      if (typeof mail.token !== "string" || !TOKEN_HEX_REGEX.test(mail.token)) {
        throw new Error("Invalid password reset token: must be 64-character lowercase hexadecimal");
      }

      if (signal.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error("Operation aborted");
      }

      const { promise, resolve, reject } = Promise.withResolvers<void>();
      let settled = false;
      let socket: net.Socket | null = null;
      const responseChunks: Buffer[] = [];
      let totalBytes = 0;

      const cleanup = () => {
        signal.removeEventListener("abort", onAbort);
        if (socket) {
          socket.removeAllListeners();
        }
      };

      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (socket) {
          socket.destroy();
          socket = null;
        }
        reject(err);
      };

      const succeed = () => {
        if (settled) return;
        settled = true;
        cleanup();
        if (socket) {
          socket.end();
          socket.destroy();
          socket = null;
        }
        resolve();
      };

      const onAbort = () => {
        fail(signal.reason instanceof Error ? signal.reason : new Error("Operation aborted"));
      };

      signal.addEventListener("abort", onAbort, { once: true });

      try {
        socket = net.createConnection({ path: normalizedSocketPath }, () => {
          if (settled || !socket) return;
          const payload =
            JSON.stringify({
              recipient: mail.recipient,
              token: mail.token,
            }) + "\n";

          socket.end(payload, "utf8");
        });
      } catch {
        fail(new Error("Failed to initiate connection to password reset mail bridge"));
        return promise;
      }

      socket.on("data", (chunk: Buffer) => {
        if (settled) return;
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          fail(new Error("Password reset mail bridge response exceeded maximum allowed size"));
          return;
        }
        responseChunks.push(chunk);

        const combined = Buffer.concat(responseChunks);
        const newlineIdx = combined.indexOf(0x0a); // '\n'
        if (newlineIdx !== -1) {
          const lineBuf = combined.subarray(0, newlineIdx);
          const remaining = combined.subarray(newlineIdx + 1);
          if (remaining.length > 0) {
            fail(new Error("Password reset mail bridge sent unexpected trailing data"));
            return;
          }

          let parsed: unknown;
          try {
            parsed = JSON.parse(lineBuf.toString("utf8"));
          } catch {
            fail(new Error("Invalid JSON response from password reset mail bridge"));
            return;
          }

          if (
            typeof parsed === "object" &&
            parsed !== null &&
            Object.keys(parsed).length === 1 &&
            "ok" in parsed &&
            parsed.ok === true
          ) {
            succeed();
          } else {
            fail(new Error("Password reset mail delivery rejected by bridge"));
          }
        }
      });

      socket.on("error", (err: NodeJS.ErrnoException) => {
        const code = typeof err?.code === "string" ? err.code : "UNKNOWN";
        fail(new Error(`Password reset mail bridge error: ${code}`));
      });

      socket.on("close", () => {
        if (!settled) {
          fail(new Error("Password reset mail bridge closed connection unexpectedly"));
        }
      });

      return promise;
    },
  };
}

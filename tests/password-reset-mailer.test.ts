import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, type Subprocess } from "bun";
import { createUnixPasswordResetMailer } from "../src/core/auth/password-reset-mailer";

// Platform-clock polling wait for spawned Python subprocess to initialize and bind Unix domain socket.
async function waitForSocket(socketPath: string, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(socketPath)) {
      try {
        const sock = net.createConnection({ path: socketPath });
        const { promise, resolve, reject } = Promise.withResolvers<void>();
        sock.on("connect", () => {
          sock.destroy();
          resolve();
        });
        sock.on("error", reject);
        await promise;
        return;
      } catch {}
    }
    const { promise, resolve } = Promise.withResolvers<void>();
    setTimeout(resolve, 50);
    await promise;
  }
  throw new Error(`Socket ${socketPath} not ready within ${timeoutMs}ms`);
}

describe("PasswordResetMailer - Input Validation & Resource Safety", () => {
  it("throws synchronously if socketPath is empty or invalid", () => {
    expect(() => createUnixPasswordResetMailer("")).toThrow(TypeError);
    expect(() => createUnixPasswordResetMailer("   ")).toThrow(TypeError);
    expect(() => createUnixPasswordResetMailer(null as unknown as string)).toThrow(TypeError);
    expect(() => createUnixPasswordResetMailer(undefined as unknown as string)).toThrow(TypeError);
  });

  it("throws TypeError if AbortSignal is missing", async () => {
    const mailer = createUnixPasswordResetMailer("/tmp/nonexistent.sock");
    const validToken = "a".repeat(64);
    await expect(
      mailer.send(
        { recipient: "user@example.com", token: validToken },
        undefined as unknown as AbortSignal
      )
    ).rejects.toThrow(TypeError);
  });

  it("rejects immediately with invalid recipient parameters", async () => {
    const mailer = createUnixPasswordResetMailer("/tmp/nonexistent.sock");
    const validToken = "a".repeat(64);
    const signal = new AbortController().signal;

    await expect(mailer.send({ recipient: "", token: validToken }, signal)).rejects.toThrow();
    await expect(
      mailer.send({ recipient: "bad\nemail@example.com", token: validToken }, signal)
    ).rejects.toThrow();
    await expect(
      mailer.send({ recipient: "bad\remail@example.com", token: validToken }, signal)
    ).rejects.toThrow();
    await expect(
      mailer.send({ recipient: " user@example.com", token: validToken }, signal)
    ).rejects.toThrow();
    await expect(
      mailer.send({ recipient: "-dash@example.com", token: validToken }, signal)
    ).rejects.toThrow();
    await expect(
      mailer.send({ recipient: "a".repeat(250) + "@example.com", token: validToken }, signal)
    ).rejects.toThrow();
  });

  it("rejects immediately with invalid token parameters", async () => {
    const mailer = createUnixPasswordResetMailer("/tmp/nonexistent.sock");
    const recipient = "user@example.com";
    const signal = new AbortController().signal;

    await expect(mailer.send({ recipient, token: "g".repeat(64) }, signal)).rejects.toThrow();
    await expect(mailer.send({ recipient, token: "A".repeat(64) }, signal)).rejects.toThrow();
    await expect(mailer.send({ recipient, token: "a".repeat(63) }, signal)).rejects.toThrow();
    await expect(mailer.send({ recipient, token: "a".repeat(65) }, signal)).rejects.toThrow();
    await expect(
      mailer.send({ recipient, token: " " + "a".repeat(63) }, signal)
    ).rejects.toThrow();
  });

  it("rejects immediately if AbortSignal is already aborted", async () => {
    const mailer = createUnixPasswordResetMailer("/tmp/nonexistent.sock");
    const controller = new AbortController();
    controller.abort(new Error("Pre-aborted"));

    await expect(
      mailer.send({ recipient: "user@example.com", token: "f".repeat(64) }, controller.signal)
    ).rejects.toThrow("Pre-aborted");
  });

  it("fails safely if socket does not exist without leaking secrets", async () => {
    const mailer = createUnixPasswordResetMailer(
      path.join(os.tmpdir(), `nonexistent-${Date.now()}-${Math.random()}.sock`)
    );
    const signal = new AbortController().signal;
    await expect(
      mailer.send({ recipient: "user@example.com", token: "c".repeat(64) }, signal)
    ).rejects.toThrow(/ENOENT/);
  });

  it("rejects malformed bridge response containing token/recipient without leaking them in error", async () => {
    const socketPath = path.join(os.tmpdir(), `test-bridge-leak-${Date.now()}.sock`);
    const secretToken = "deadbeef".repeat(8);
    const secretRecipient = "victim@example.com";

    const server = net.createServer((c) => {
      c.on("data", () => {
        c.write(`{malformed-raw-secret: "${secretToken}", recipient: "${secretRecipient}"}\n`);
      });
    });

    const { promise, resolve } = Promise.withResolvers<void>();
    server.listen(socketPath, resolve);
    await promise;

    try {
      const mailer = createUnixPasswordResetMailer(socketPath);
      const signal = new AbortController().signal;

      let caughtError: Error | null = null;
      try {
        await mailer.send({ recipient: secretRecipient, token: secretToken }, signal);
      } catch (err: unknown) {
        caughtError = err instanceof Error ? err : new Error(String(err));
      }

      expect(caughtError).not.toBeNull();
      expect(caughtError!.message).not.toContain(secretToken);
      expect(caughtError!.message).not.toContain(secretRecipient);
    } finally {
      server.close();
      try {
        fs.unlinkSync(socketPath);
      } catch {}
    }
  });

  it("rejects bridge response with trailing data without leaking secrets", async () => {
    const socketPath = path.join(os.tmpdir(), `test-bridge-trailing-${Date.now()}.sock`);
    const secretToken = "12345678".repeat(8);

    const server = net.createServer((c) => {
      c.on("data", () => {
        c.write(`{"ok":true}\nextra-trailing-data-secret-${secretToken}\n`);
      });
    });

    const { promise, resolve } = Promise.withResolvers<void>();
    server.listen(socketPath, resolve);
    await promise;

    try {
      const mailer = createUnixPasswordResetMailer(socketPath);
      const signal = new AbortController().signal;

      let caughtError: Error | null = null;
      try {
        await mailer.send({ recipient: "test@example.com", token: secretToken }, signal);
      } catch (err: unknown) {
        caughtError = err instanceof Error ? err : new Error(String(err));
      }

      expect(caughtError).not.toBeNull();
      expect(caughtError!.message).not.toContain(secretToken);
    } finally {
      server.close();
      try {
        fs.unlinkSync(socketPath);
      } catch {}
    }
  });

  it("aborts in-flight request cleanly when signal fires", async () => {
    const socketPath = path.join(os.tmpdir(), `test-bridge-abort-${Date.now()}.sock`);
    const { promise: connectedPromise, resolve: notifyConnected } = Promise.withResolvers<void>();

    const server = net.createServer((_c) => {
      notifyConnected();
    });

    const { promise: listenPromise, resolve: notifyListening } = Promise.withResolvers<void>();
    server.listen(socketPath, notifyListening);
    await listenPromise;

    try {
      const mailer = createUnixPasswordResetMailer(socketPath);
      const controller = new AbortController();

      const sendPromise = mailer.send(
        { recipient: "alice@example.com", token: "1".repeat(64) },
        controller.signal
      );

      await connectedPromise;
      controller.abort(new Error("Timeout aborted"));

      await expect(sendPromise).rejects.toThrow("Timeout aborted");
    } finally {
      server.close();
      try {
        fs.unlinkSync(socketPath);
      } catch {}
    }
  });
});

describe("PasswordResetMailer - Real Helper & Synthetic Process Sink", () => {
  let tmpDir: string;
  let socketDir: string;
  let socketPath: string;
  let sinkLog: string;
  let sinkScript: string;
  let helperProc: Subprocess | null = null;
  const pythonScript = path.resolve("deploy/mail-helper/usemeter-mail-bridge.py");
  const validToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  function getUnixUid(): number {
    if (typeof process.getuid !== "function") {
      throw new Error("POSIX process.getuid is required on this platform");
    }
    return process.getuid();
  }

  async function startHelperProcess(extraArgs: string[] = []): Promise<Subprocess> {
    const proc = spawn({
      cmd: [
        "python3",
        pythonScript,
        "--socket-path",
        socketPath,
        "--sendmail-bin",
        sinkScript,
        "--public-origin",
        "https://usemeter.example.com",
        "--sender",
        "usemeter@example.com",
        "--allowed-uids",
        `1000,1000,${getUnixUid()}`,
        ...extraArgs,
      ],
      stdout: "pipe",
      stderr: "pipe",
    });
    helperProc = proc;
    try {
      await waitForSocket(socketPath, 3000);
    } catch (err) {
      proc.kill();
      await proc.exited;
      helperProc = null;
      throw err;
    }
    return proc;
  }

  async function stopHelperProcess(proc: Subprocess | null) {
    if (proc) {
      proc.kill();
      await proc.exited;
    }
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mail-suite-"));
    socketDir = path.join(tmpDir, "sockets");
    fs.mkdirSync(socketDir, { mode: 0o770 });
    socketPath = path.join(socketDir, "bridge.sock");
    sinkLog = path.join(tmpDir, "sink.log");
    sinkScript = path.join(tmpDir, "mock-sendmail.sh");

    // Synthetic process sink: captures argv and stdin
    fs.writeFileSync(
      sinkScript,
      `#!/usr/bin/env bash
echo "--- SUBMISSION ---" >> "${sinkLog}"
echo "ARGS: $@" >> "${sinkLog}"
echo "STDIN:" >> "${sinkLog}"
cat >> "${sinkLog}"
echo "--- END ---" >> "${sinkLog}"
exit 0
`,
      { mode: 0o755 }
    );

    helperProc = await startHelperProcess();
  });

  afterAll(async () => {
    await stopHelperProcess(helperProc);
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  });

  it("submits valid email via helper to synthetic sendmail sink with canonical fragment and strict argv", async () => {
    const mailer = createUnixPasswordResetMailer(socketPath);
    const signal = new AbortController().signal;

    const initialSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    await mailer.send({ recipient: "testuser@example.com", token: validToken }, signal);

    const logContent = fs.readFileSync(sinkLog, "utf8");
    const newEntry = logContent.slice(initialSize);

    // Verify argv: -oi -f <sender> -- <recipient>
    // Verify structure, strict argv, and token fragment without English prose pinning
    expect(newEntry).toContain("ARGS: -oi -f usemeter@example.com -- testuser@example.com");
    expect(newEntry).toContain("https://usemeter.example.com/reset-password#token=" + validToken);
    expect(newEntry).toContain("From: useMeter <usemeter@example.com>");
    expect(newEntry).toContain("To: <testuser@example.com>");
    expect(newEntry).toMatch(/Subject:\s+/i);
    expect(newEntry).toContain("Auto-Submitted: auto-generated");
  });

  it("rejects delivery when sendmail binary exits non-zero", async () => {
    const failingSink = path.join(tmpDir, "failing-sendmail.sh");
    fs.writeFileSync(failingSink, `#!/usr/bin/env bash\nexit 1\n`, { mode: 0o755 });

    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess(["--sendmail-bin", failingSink]);

    const mailer = createUnixPasswordResetMailer(socketPath);
    const signal = new AbortController().signal;

    await expect(
      mailer.send({ recipient: "failuser@example.com", token: validToken }, signal)
    ).rejects.toThrow();

    // Restore normal helper
    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess();
  });

  it("rejects connection when peer UID is unauthorized without submitting", async () => {
    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess(["--allowed-uids", "999999"]);

    const mailer = createUnixPasswordResetMailer(socketPath);
    const signal = new AbortController().signal;

    const initialSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    await expect(
      mailer.send({ recipient: "peercheck@example.com", token: validToken }, signal)
    ).rejects.toThrow();

    const afterSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    expect(afterSize).toBe(initialSize);

    // Restore normal helper
    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess();
  });
  it("rejects request with coalesced trailing data without submitting", async () => {
    const rawSock = net.createConnection({ path: socketPath });
    const { promise, resolve } = Promise.withResolvers<string>();

    const initialSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    rawSock.on("connect", () => {
      const payload =
        JSON.stringify({ recipient: "coalesced@example.com", token: validToken }) + "\n";
      rawSock.end(payload + "extra-data-in-flight\n", "utf8");
    });

    let resp = "";
    rawSock.on("data", (chunk) => {
      resp += chunk.toString("utf8");
    });
    rawSock.on("close", () => resolve(resp));

    const reply = await promise;
    expect(reply).toContain('{"ok":false}');

    const afterSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    expect(afterSize).toBe(initialSize);
  });

  it("rejects request when client pauses without half-closing connection", async () => {
    const rawSock = net.createConnection({ path: socketPath });
    const { promise, resolve } = Promise.withResolvers<string>();

    const initialSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    rawSock.on("connect", () => {
      const payload =
        JSON.stringify({ recipient: "no-eof@example.com", token: validToken }) + "\n";
      rawSock.write(payload);
    });

    let resp = "";
    rawSock.on("data", (chunk) => {
      resp += chunk.toString("utf8");
    });
    rawSock.on("close", () => resolve(resp));

    const reply = await promise;
    expect(reply).toContain('{"ok":false}');

    const afterSize = fs.existsSync(sinkLog) ? fs.statSync(sinkLog).size : 0;
    expect(afterSize).toBe(initialSize);
  });


  it("reconnects seamlessly after helper process restarts via persistent directory mount", async () => {
    const mailer = createUnixPasswordResetMailer(socketPath);
    const signal1 = new AbortController().signal;
    await mailer.send({ recipient: "first@example.com", token: validToken }, signal1);

    // Restart helper (directory persists)
    await stopHelperProcess(helperProc);
    expect(fs.existsSync(socketDir)).toBe(true);

    helperProc = await startHelperProcess();

    // Second send on same mailer instance
    const secondToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const signal2 = new AbortController().signal;
    await mailer.send({ recipient: "second@example.com", token: secondToken }, signal2);

    const logContent = fs.readFileSync(sinkLog, "utf8");
    expect(logContent).toContain("second@example.com");
    expect(logContent).toContain(secondToken);
  });

  it("kills and reaps descendant process group when client disconnects during submission", async () => {
    const slowSink = path.join(tmpDir, "slow-descendant-sink.sh");
    const descendantPidFile = path.join(tmpDir, "descendant.pid");

    fs.writeFileSync(
      slowSink,
      `#!/usr/bin/env bash
(
  sleep 30 &
  echo $! > "${descendantPidFile}"
  wait
) &
wait
exit 0
`,
      { mode: 0o755 }
    );

    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess(["--sendmail-bin", slowSink]);

    const clientSock = net.createConnection({ path: socketPath });
    clientSock.on("error", () => {});
    clientSock.on("connect", () => {
      const payload =
        JSON.stringify({ recipient: "abort@example.com", token: validToken }) + "\n";
      clientSock.end(payload, "utf8");
    });

    let descendantPid = 0;
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      if (fs.existsSync(descendantPidFile)) {
        const content = fs.readFileSync(descendantPidFile, "utf8").trim();
        if (content.length > 0) {
          descendantPid = parseInt(content, 10);
          break;
        }
      }
      const { promise, resolve } = Promise.withResolvers<void>();
      setTimeout(resolve, 30);
      await promise;
    }

    expect(descendantPid).toBeGreaterThan(0);

    // Abort connection
    clientSock.destroy();

    // Helper must kill process group (including descendantPid) and reap it
    let reaped = false;
    const reapDeadline = Date.now() + 3000;
    while (Date.now() < reapDeadline) {
      try {
        process.kill(descendantPid, 0);
        const { promise, resolve } = Promise.withResolvers<void>();
        setTimeout(resolve, 30);
        await promise;
      } catch {
        reaped = true;
        break;
      }
    }

    expect(reaped).toBe(true);

    // Restore normal helper
    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess();
  });

  it("kills and reaps descendant process group when helper is stopped during submission", async () => {
    const slowSink = path.join(tmpDir, "slow-stop-sink.sh");
    const descendantPidFile = path.join(tmpDir, "descendant-stop.pid");

    fs.writeFileSync(
      slowSink,
      `#!/usr/bin/env bash
(
  sleep 30 &
  echo $! > "${descendantPidFile}"
  wait
) &
wait
exit 0
`,
      { mode: 0o755 }
    );

    await stopHelperProcess(helperProc);
    helperProc = await startHelperProcess(["--sendmail-bin", slowSink]);

    const clientSock = net.createConnection({ path: socketPath });
    clientSock.on("error", () => {});
    clientSock.on("connect", () => {
      const payload =
        JSON.stringify({ recipient: "stop-test@example.com", token: validToken }) + "\n";
      clientSock.end(payload, "utf8");
    });

    let descendantPid = 0;
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      if (fs.existsSync(descendantPidFile)) {
        const content = fs.readFileSync(descendantPidFile, "utf8").trim();
        if (content.length > 0) {
          descendantPid = parseInt(content, 10);
          break;
        }
      }
      const { promise, resolve } = Promise.withResolvers<void>();
      setTimeout(resolve, 30);
      await promise;
    }

    expect(descendantPid).toBeGreaterThan(0);

    // Stop helper while child is running in-flight
    try {
      await stopHelperProcess(helperProc);
      helperProc = null;
    } finally {
      clientSock.destroy();
    }

    // Descendant process group must be reaped immediately
    let reaped = false;
    try {
      process.kill(descendantPid, 0);
    } catch {
      reaped = true;
    }

    expect(reaped).toBe(true);

    // Restore normal helper
    helperProc = await startHelperProcess();
  });
});

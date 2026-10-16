import { describe, expect, it } from "bun:test";
import { spawn } from "bun";
import * as path from "node:path";

const monitorDirectory = path.resolve("deploy/monitor");

async function runPythonJson(source: string): Promise<Record<string, unknown>> {
  const prelude = `import importlib.util, pathlib, sys; monitor_path = pathlib.Path(${JSON.stringify(path.join(monitorDirectory, "usemeter-monitor.py"))}); spec = importlib.util.spec_from_file_location("usemeter_monitor", monitor_path); m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m; spec.loader.exec_module(m); `;
  const environment: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === "string") environment[key] = value;
  }
  environment["PYTHONDONTWRITEBYTECODE"] = "1";
  const proc = spawn({
    cmd: ["python3", "-c", prelude + source],
    env: environment,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdoutStream = proc.stdout;
  const stderrStream = proc.stderr;
  if (!stdoutStream || !stderrStream) throw new Error("Python monitor test streams are unavailable");
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(stdoutStream).text(),
    new Response(stderrStream).text(),
    proc.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`Python monitor behavior check failed (${exitCode}): ${stderr || stdout}`);
  }
  const output: unknown = JSON.parse(stdout);
  if (!output || typeof output !== "object" || Array.isArray(output)) {
    throw new Error("Python monitor behavior check returned invalid JSON shape");
  }
  return Object.fromEntries(Object.entries(output));
}

const configSource = `
cfg = m.config_from_values({
    "USEMETER_MONITOR_ENABLED": "1",
    "USEMETER_MONITOR_HEALTH_URL": "https://usemeter.example.com/health",
    "USEMETER_MONITOR_RECIPIENT": "recipient@example.com",
    "USEMETER_MONITOR_SENDER": "sender@example.com",
})
`;

describe("useMeter host monitor", () => {
  it("sends only status transitions and preserves recovery through the global cooldown", async () => {
    const result = await runPythonJson(`
import importlib.util, json, sys, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    clock = [1000]
    observed = {"health": True, "disk": 20.0}
    messages = []
    def health_probe(_url): return observed["health"]
    def disk_probe(): return observed["disk"]
    def sendmail(sender, recipient, message):
        messages.append((sender, recipient, message.split(b"\\r\\n\\r\\n", 1)[1].decode()))
    healthy = m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    healthy_firstboot_has_no_state = not (state_dir / m.STATE_FILE_NAME).exists()
    observed.update(health=False, disk=95.0)
    first_alert = m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    clock[0] = 1050
    observed["disk"] = 97.0
    repeated = m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    clock[0] = 1100
    observed.update(health=True, disk=20.0)
    pending_recovery = m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    spec = importlib.util.spec_from_file_location("monitor_after_restart", pathlib.Path(m.__file__))
    fresh = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fresh
    spec.loader.exec_module(fresh)
    fresh_config = fresh.config_from_values({
        "USEMETER_MONITOR_ENABLED": "1",
        "USEMETER_MONITOR_HEALTH_URL": "https://usemeter.example.com/health",
        "USEMETER_MONITOR_RECIPIENT": "recipient@example.com",
        "USEMETER_MONITOR_SENDER": "sender@example.com",
    })
    clock[0] = 1599
    still_cooling = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    clock[0] = 1600
    recovery = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    clock[0] = 1601
    observed.update(health=False, disk=95.0)
    new_incident_cooling = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    clock[0] = 2200
    new_incident = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
    print(json.dumps({
        "healthyFirstboot": healthy["wouldNotify"] is False and healthy_firstboot_has_no_state,
        "sentCount": len(messages),
        "repeatWasSuppressed": repeated["wouldNotify"] is False,
        "recoveryStayedPending": pending_recovery["wouldNotify"] is True and pending_recovery["cooldownRemainingSeconds"] == 500,
        "cooldownWasGlobal": still_cooling["cooldownRemainingSeconds"] == 1 and new_incident_cooling["cooldownRemainingSeconds"] == 599,
        "recoveryBody": messages[1][2],
        "recoverySent": recovery["activeAlerts"] == [] and len(messages) >= 2,
        "newIncidentSentAfterCooldown": len(messages) == 3 and new_incident["activeAlerts"] == ["disk", "health"],
        "stateFileMode": (state_dir / m.STATE_FILE_NAME).stat().st_mode & 0o777,
    }))
`);
    expect(result["healthyFirstboot"]).toBe(true);
    expect(result["sentCount"]).toBe(3);
    expect(result["repeatWasSuppressed"]).toBe(true);
    expect(result["recoveryStayedPending"]).toBe(true);
    expect(result["cooldownWasGlobal"]).toBe(true);
    expect(result["recoverySent"]).toBe(true);
    expect(result["recoveryBody"]).toContain("Disk status: OK (20.0%; threshold 90%).");
    expect(result["recoveryBody"]).toContain("Health status: healthy.");
    expect(result["stateFileMode"]).toBe(0o600);
  });

  it("does not truncate fractional time when enforcing the ten-minute minimum", async () => {
    const result = await runPythonJson(`
import importlib.util, json, sys, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    clock = [1000.9]
    observed = {"disk": 95.0}
    sends = []
    def sendmail(*_args): sends.append("accepted")
    first = m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=lambda _url: True, disk_probe=lambda: observed["disk"], mail_sender=sendmail)
    spec = importlib.util.spec_from_file_location("monitor_fractional_restart", pathlib.Path(m.__file__))
    fresh = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fresh
    spec.loader.exec_module(fresh)
    fresh_config = fresh.config_from_values({
        "USEMETER_MONITOR_ENABLED": "1",
        "USEMETER_MONITOR_HEALTH_URL": "https://usemeter.example.com/health",
        "USEMETER_MONITOR_RECIPIENT": "recipient@example.com",
        "USEMETER_MONITOR_SENDER": "sender@example.com",
    })
    clock[0] = 1600.0
    observed["disk"] = 20.0
    before_full_interval = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=lambda _url: True, disk_probe=lambda: observed["disk"], mail_sender=sendmail)
    count_before_full_interval = len(sends)
    clock[0] = 1600.9
    after_full_interval = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=lambda _url: True, disk_probe=lambda: observed["disk"], mail_sender=sendmail)
    print(json.dumps({
        "first": first,
        "beforeFullInterval": before_full_interval,
        "countBeforeFullInterval": count_before_full_interval,
        "afterFullInterval": after_full_interval,
        "sendCount": len(sends),
    }))
`);
    expect(result["countBeforeFullInterval"]).toBe(1);
    expect(result["beforeFullInterval"]).toMatchObject({ wouldNotify: true, cooldownRemainingSeconds: 1 });
    expect(result["sendCount"]).toBe(2);
    expect(result["afterFullInterval"]).toMatchObject({ submissionAccepted: true, activeAlerts: [] });
  });

  
  it("check-only collects observations but never sends or advances delivery state", async () => {
    const result = await runPythonJson(`
import json, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    observed = []
    def health_probe(url): observed.append(("health", url)); return False
    def disk_probe(): observed.append(("disk",)); return 92.5
    def sendmail(*_args): raise AssertionError("check-only attempted delivery")
    report = m.run_once(cfg, state_directory=state_dir, now_fn=lambda: 1000, health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail, check_only=True)
    print(json.dumps({"report": report, "observed": observed, "stateExists": (state_dir / m.STATE_FILE_NAME).exists()}))
`);
    expect(result["report"]).toMatchObject({
      mode: "check-only",
      healthHealthy: false,
      diskUsagePercent: 92.5,
      activeAlerts: ["disk", "health"],
      wouldNotify: true,
    });
    expect(result["observed"]).toHaveLength(2);
    expect(result["stateExists"]).toBe(false);
  });

  it("runs the CLI check-only path against a local health fixture without queueing mail", async () => {
    const result = await runPythonJson(`
import contextlib, http.server, importlib.util, io, json, os, pathlib, sys, tempfile, threading
with tempfile.TemporaryDirectory() as tmp:
    home = pathlib.Path(tmp) / "home"
    config_dir = home / ".config" / "usemeter"
    config_dir.mkdir(parents=True, mode=0o700)
    marker = pathlib.Path(tmp) / "sendmail-called"
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args): pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config_path = config_dir / "monitor.env"
    config_path.write_text(chr(10).join([
        "USEMETER_MONITOR_ENABLED=1",
        f"USEMETER_MONITOR_HEALTH_URL=http://127.0.0.1:{server.server_port}/health",
        "USEMETER_MONITOR_RECIPIENT=recipient@example.invalid",
        "USEMETER_MONITOR_SENDER=sender@example.invalid",
        "",
    ]))
    config_path.chmod(0o600)
    old_home = os.environ.get("HOME")
    saved_env = {key: os.environ.pop(key, None) for key in m.CONFIG_KEYS}
    os.environ["HOME"] = str(home)
    try:
        spec = importlib.util.spec_from_file_location("usemeter_monitor_cli_test", pathlib.Path(m.__file__))
        cli_monitor = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cli_monitor
        spec.loader.exec_module(cli_monitor)
        def capture_sendmail(*_args, **_kwargs): marker.write_text("would queue")
        cli_monitor.send_mail = capture_sendmail
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = cli_monitor.main(["--check-only"])
        report = json.loads(output.getvalue())
        state_exists = (cli_monitor.STATE_DIR / cli_monitor.STATE_FILE_NAME).exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if old_home is None: os.environ.pop("HOME", None)
        else: os.environ["HOME"] = old_home
        for key, value in saved_env.items():
            if value is not None: os.environ[key] = value
    print(json.dumps({
        "exitCode": exit_code,
        "report": report,
        "mailQueued": marker.exists(),
        "stateExists": state_exists,
    }))
`);
    expect(result["exitCode"]).toBe(0);
    const report = result["report"];
    if (
      !report ||
      typeof report !== "object" ||
      Array.isArray(report) ||
      !("mode" in report) ||
      report["mode"] !== "check-only" ||
      !("healthHealthy" in report) ||
      report["healthHealthy"] !== false ||
      !("wouldNotify" in report) ||
      report["wouldNotify"] !== true ||
      !("activeAlerts" in report) ||
      !Array.isArray(report["activeAlerts"]) ||
      !report["activeAlerts"].includes("health")
    ) {
      throw new Error("CLI check-only report did not include the unhealthy observation");
    }
    expect(result["mailQueued"]).toBe(false);
    expect(result["stateExists"]).toBe(false);
  });
  
  it("keeps failed notifications retriable but rate-limits the next submission attempt", async () => {
    const result = await runPythonJson(`
import importlib.util, json, sys, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    clock = [500.0]
    sends = []
    def health_probe(_url): return True
    def disk_probe(): return 95.0
    def fail(_sender, _recipient, _message):
        sends.append("failed")
        raise m.MailSubmissionError("local mail submission failed", outcome_uncertain=False)
    try:
        m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=fail)
    except m.MailSubmissionError:
        pass
    spec = importlib.util.spec_from_file_location("monitor_retry_restart", pathlib.Path(m.__file__))
    fresh = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fresh
    spec.loader.exec_module(fresh)
    fresh_config = fresh.config_from_values({
        "USEMETER_MONITOR_ENABLED": "1",
        "USEMETER_MONITOR_HEALTH_URL": "https://usemeter.example.com/health",
        "USEMETER_MONITOR_RECIPIENT": "recipient@example.com",
        "USEMETER_MONITOR_SENDER": "sender@example.com",
    })
    def succeed(_sender, _recipient, _message): sends.append("accepted")
    clock[0] = 1099.999
    before_cooldown = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=succeed)
    clock[0] = 1100.0
    retry = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], health_probe=health_probe, disk_probe=disk_probe, mail_sender=succeed)
    print(json.dumps({
        "sends": sends,
        "beforeCooldown": before_cooldown,
        "retry": retry,
    }))
`);
    expect(result["sends"]).toEqual(["failed", "accepted"]);
    expect(result["beforeCooldown"]).toMatchObject({
      activeAlerts: ["disk"],
      wouldNotify: true,
      cooldownRemainingSeconds: 1,
    });
    expect(result["retry"]).toMatchObject({ activeAlerts: ["disk"], wouldNotify: false });
  });
  
  it("does not invoke mail when the durable pre-send admission write fails", async () => {
    const result = await runPythonJson(`
import json, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    sends = []
    original_save = m._save_state
    def fail_save(_directory, _state): raise m.MonitorError("state write failed")
    m._save_state = fail_save
    try:
        try:
            m.run_once(cfg, state_directory=state_dir, now_fn=lambda: 1000, health_probe=lambda _url: False, disk_probe=lambda: 20.0, mail_sender=lambda *_args: sends.append("called"))
        except m.MonitorError:
            failed = True
        else:
            failed = False
    finally:
        m._save_state = original_save
    print(json.dumps({"failed": failed, "sends": sends, "stateExists": (state_dir / m.STATE_FILE_NAME).exists()}))
`);
    expect(result).toEqual({ failed: true, sends: [], stateExists: false });
  });

  it("fails closed when durable admission exceeds its reserved window", async () => {
    const result = await runPythonJson(`
import importlib.util, json, sys, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    clock = [1000.0]
    monotonic = [0.0]
    submissions = []
    original_save = m._save_state
    def slow_save(directory, state):
        original_save(directory, state)
        clock[0] += 8.0
        monotonic[0] += 8.0
    m._save_state = slow_save
    try:
        try:
            m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], monotonic_fn=lambda: monotonic[0], health_probe=lambda _url: True, disk_probe=lambda: 95.0, mail_sender=lambda *_args: submissions.append("accepted"))
        except m.MonitorError:
            failed = True
        else:
            failed = False
    finally:
        m._save_state = original_save
    spec = importlib.util.spec_from_file_location("monitor_slow_admission_restart", pathlib.Path(m.__file__))
    fresh = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fresh
    spec.loader.exec_module(fresh)
    fresh_config = fresh.config_from_values({
        "USEMETER_MONITOR_ENABLED": "1",
        "USEMETER_MONITOR_HEALTH_URL": "https://usemeter.example.com/health",
        "USEMETER_MONITOR_RECIPIENT": "recipient@example.com",
        "USEMETER_MONITOR_SENDER": "sender@example.com",
    })
    restart_check = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], monotonic_fn=lambda: monotonic[0], health_probe=lambda _url: True, disk_probe=lambda: 95.0, mail_sender=lambda *_args: submissions.append("accepted"))
    print(json.dumps({"failed": failed, "submissions": submissions, "restartCheck": restart_check}))
`);
    expect(result["failed"]).toBe(true);
    expect(result["submissions"]).toEqual([]);
    expect(result["restartCheck"]).toMatchObject({
      mode: "monitor",
      wouldNotify: true,
      cooldownRemainingSeconds: 607,
    });
  });

  it("reserves an absolute retry deadline across admission fsync and uncertain MTA acceptance", async () => {
    const result = await runPythonJson(`
import importlib.util, json, sys, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    clock = [1000.9]
    monotonic = [0.0]
    submissions = []
    original_save = m._save_state
    save_calls = [0]
    def fail_final_save(directory, state):
        save_calls[0] += 1
        if save_calls[0] == 2: raise m.MonitorError("simulated post-submission state failure")
        original_save(directory, state)
        clock[0] += 4.0
        monotonic[0] += 4.0
    m._save_state = fail_final_save
    def accept_slowly(_sender, _recipient, _message):
        submissions.append("accepted")
        clock[0] += 9.0
        monotonic[0] += 9.0
    try:
        try:
            m.run_once(cfg, state_directory=state_dir, now_fn=lambda: clock[0], monotonic_fn=lambda: monotonic[0], health_probe=lambda _url: True, disk_probe=lambda: 95.0, mail_sender=accept_slowly)
        except m.MonitorError:
            post_accept_write_failed = True
        else:
            post_accept_write_failed = False
    finally:
        m._save_state = original_save
    spec = importlib.util.spec_from_file_location("monitor_uncertain_restart", pathlib.Path(m.__file__))
    fresh = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fresh
    spec.loader.exec_module(fresh)
    fresh_config = fresh.config_from_values({
        "USEMETER_MONITOR_ENABLED": "1",
        "USEMETER_MONITOR_HEALTH_URL": "https://usemeter.example.com/health",
        "USEMETER_MONITOR_RECIPIENT": "recipient@example.com",
        "USEMETER_MONITOR_SENDER": "sender@example.com",
    })
    clock[0] = 1613.8
    before_deadline = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], monotonic_fn=lambda: monotonic[0], health_probe=lambda _url: True, disk_probe=lambda: 95.0, mail_sender=lambda *_args: submissions.append("accepted"))
    sends_before_deadline = len(submissions)
    clock[0] = 1615.9
    retry_after_deadline = fresh.run_once(fresh_config, state_directory=state_dir, now_fn=lambda: clock[0], monotonic_fn=lambda: monotonic[0], health_probe=lambda _url: True, disk_probe=lambda: 95.0, mail_sender=lambda *_args: submissions.append("accepted"))
    print(json.dumps({
        "postAcceptWriteFailed": post_accept_write_failed,
        "sendsBeforeDeadline": sends_before_deadline,
        "beforeDeadline": before_deadline,
        "submissions": submissions,
        "retry": retry_after_deadline,
    }))
`);
    expect(result["postAcceptWriteFailed"]).toBe(true);
    expect(result["sendsBeforeDeadline"]).toBe(1);
    expect(result["beforeDeadline"]).toMatchObject({ wouldNotify: true, cooldownRemainingSeconds: 3 });
    expect(result["submissions"]).toEqual(["accepted", "accepted"]);
    expect(result["retry"]).toMatchObject({ submissionAccepted: true, wouldNotify: false });
  });

  it("manual send-test submits once through configured addresses without advancing state", async () => {
    const result = await runPythonJson(`
import json, tempfile
from pathlib import Path
cfg = m.config_from_values({
    "USEMETER_MONITOR_ENABLED": "0",
    "USEMETER_MONITOR_RECIPIENT": "recipient@example.invalid",
    "USEMETER_MONITOR_SENDER": "sender@example.invalid",
})
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    sent = []
    def sendmail(sender, recipient, _message): sent.append((sender, recipient))
    report = m.run_once(cfg, state_directory=state_dir, mail_sender=sendmail, send_test=True)
    print(json.dumps({
        "report": report,
        "envelope": sent[0],
        "stateExists": (state_dir / m.STATE_FILE_NAME).exists(),
    }))
`);
    expect(result["report"]).toEqual({ mode: "send-test", submissionAccepted: true });
    expect(result["envelope"]).toEqual(["sender@example.invalid", "recipient@example.invalid"]);
    expect(result["stateExists"]).toBe(false);
  });

  it("rejects corrupt, unhealthy, oversized, and redirected health responses without following redirects", async () => {
    const result = await runPythonJson(`
import http.server, json, threading
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests += 1
        status, body, headers = self.server.reply
        self.send_response(status)
        for key, value in headers.items(): self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.requests = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
url = f"http://127.0.0.1:{server.server_port}/health"
try:
    cases = []
    for status, body, headers, expected in [
        (200, b"{bad json", {}, False),
        (200, b'{"status":"ok","integrity":"true","pollerRunning":true}', {}, False),
        (200, b'{"status":"ok","integrity":true,"pollerRunning":true}', {}, True),
        (200, b"x" * (m.MAX_HEALTH_BODY_BYTES + 1), {}, False),
        (200, b"[" * 1500 + b"0" + b"]" * 1500, {}, False),
        (302, b"", {"Location": "http://example.invalid/health"}, False),
    ]:
        server.reply = (status, body, headers)
        before = server.requests
        actual = m.probe_health(url)
        cases.append({"actual": actual, "expected": expected, "requests": server.requests - before})
    print(json.dumps({"cases": cases}))
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
`);
    expect(result["cases"]).toEqual([
      { actual: false, expected: false, requests: 1 },
      { actual: false, expected: false, requests: 1 },
      { actual: true, expected: true, requests: 1 },
      { actual: false, expected: false, requests: 1 },
      { actual: false, expected: false, requests: 1 },
      { actual: false, expected: false, requests: 1 },
    ]);
  });

  it("bounds the entire health request and continues to alert on a slow-trickled response", async () => {
    const result = await runPythonJson(`
import json, socket, tempfile, threading, time
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    url = f"http://127.0.0.1:{listener.getsockname()[1]}/health"
    def slow_response():
        conn, _ = listener.accept()
        try:
            request = b""
            header_end = bytes((13, 10)) * 2
            while header_end not in request:
                request += conn.recv(1024)
            conn.sendall(bytes((13, 10)).join([b"HTTP/1.1 200 OK", b"Content-Length: 100", b"Connection: keep-alive", b"", b""]))
            for _ in range(100):
                try: conn.sendall(b"x")
                except OSError: break
                time.sleep(0.02)
        except OSError:
            pass
        finally:
            conn.close()
            listener.close()
    thread = threading.Thread(target=slow_response, daemon=True)
    thread.start()
    sends = []
    started = time.monotonic()
    report = m.run_once(
        cfg,
        state_directory=state_dir,
        now_fn=lambda: 1000,
        health_probe=lambda _url: m.probe_health(url, timeout_seconds=0.25),
        disk_probe=lambda: 20.0,
        mail_sender=lambda *_args: sends.append("accepted"),
    )
    elapsed = time.monotonic() - started
    thread.join(timeout=2)
    print(json.dumps({"elapsed": elapsed, "report": report, "sends": sends, "threadStopped": not thread.is_alive()}))
`);
    expect(result["elapsed"]).toBeLessThan(1.5);
    expect(result["report"]).toMatchObject({
      activeAlerts: ["health"],
      healthHealthy: false,
      submissionAccepted: true,
    });
    expect(result["sends"]).toEqual(["accepted"]);
    expect(result["threadStopped"]).toBe(true);
  });

  it("classifies malformed HTTP status and negative chunk lengths as unhealthy", async () => {
    const result = await runPythonJson(`
import json, socket, tempfile, threading
from pathlib import Path
${configSource}
def start_response(raw):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    url = f"http://127.0.0.1:{listener.getsockname()[1]}/health"
    def serve():
        conn, _ = listener.accept()
        try:
            request = b""
            header_end = bytes((13, 10)) * 2
            while header_end not in request:
                request += conn.recv(1024)
            conn.sendall(raw)
        except OSError:
            pass
        finally:
            conn.close()
            listener.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return url, thread
eol = bytes((13, 10))
malformed_url, malformed_thread = start_response(b"NOT-HTTP" + eol + b"Content-Length: 2" + eol + eol + b"{}")
chunked_url, chunked_thread = start_response(
    b"HTTP/1.1 200 OK" + eol + b"Transfer-Encoding: chunked" + eol + b"Connection: close" + eol + eol + b"-1" + eol + b"x" * 131072
)
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    sends = []
    report = m.run_once(
        cfg,
        state_directory=state_dir,
        now_fn=lambda: 1000,
        health_probe=lambda _url: m.probe_health(malformed_url, timeout_seconds=0.5),
        disk_probe=lambda: 20.0,
        mail_sender=lambda *_args: sends.append("accepted"),
    )
    chunked_healthy = m.probe_health(chunked_url, timeout_seconds=0.5)
malformed_thread.join(timeout=2)
chunked_thread.join(timeout=2)
print(json.dumps({
    "report": report,
    "sends": sends,
    "chunkedHealthy": chunked_healthy,
    "threadsStopped": not malformed_thread.is_alive() and not chunked_thread.is_alive(),
}))
`);
    expect(result["report"]).toMatchObject({
      activeAlerts: ["health"],
      healthHealthy: false,
      submissionAccepted: true,
    });
    expect(result["sends"]).toEqual(["accepted"]);
    expect(result["chunkedHealthy"]).toBe(false);
    expect(result["threadsStopped"]).toBe(true);
  });

  
  it("rejects unsafe URLs and email header/option injection", async () => {
    const result = await runPythonJson(`
import json
failures = []
for url in [
    "ftp://usemeter.example.com/health",
    "http://example.com/health",
    "https://user:secret@usemeter.example.com/health",
    "https://usemeter.example.com/health?token=secret",
    "https://usemeter.example.com/health#fragment",
]:
    try: m.config_from_values({"USEMETER_MONITOR_HEALTH_URL": url})
    except m.MonitorError: failures.append(True)
    else: failures.append(False)
for value in ["person@example.com\\r\\nBcc: victim@example.com", "--inject@example.com"]:
    try: m.config_from_values({"USEMETER_MONITOR_RECIPIENT": value, "USEMETER_MONITOR_SENDER": "sender@example.com"})
    except m.MonitorError: failures.append(True)
    else: failures.append(False)
print(json.dumps({"failures": failures}))
`);
    expect(result["failures"]).toEqual([true, true, true, true, true, true, true]);
  });

  it("loads only private, non-shell configuration and rejects unsafe paths", async () => {
    const result = await runPythonJson(`
import json, os, tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as tmp:
    directory = Path(tmp) / "config"
    directory.mkdir(mode=0o700)
    path = directory / "monitor.env"
    path.write_text("USEMETER_MONITOR_ENABLED=0" + chr(10) + "USEMETER_MONITOR_RECIPIENT=" + chr(10))
    os.chmod(path, 0o600)
    values = m.read_config_file(path)
    valid = values == {"USEMETER_MONITOR_ENABLED": "0", "USEMETER_MONITOR_RECIPIENT": ""}
    os.chmod(path, 0o640)
    try: m.read_config_file(path)
    except m.MonitorError: unsafe_file = True
    else: unsafe_file = False
    os.chmod(path, 0o600)
    os.chmod(directory, 0o750)
    try: m.read_config_file(path)
    except m.MonitorError: unsafe_directory = True
    else: unsafe_directory = False
    os.chmod(directory, 0o700)
    link = directory / "link.env"
    link.symlink_to(path)
    try: m.read_config_file(link)
    except m.MonitorError: symlink_rejected = True
    else: symlink_rejected = False
    print(json.dumps({"valid": valid, "unsafeFile": unsafe_file, "unsafeDirectory": unsafe_directory, "symlinkRejected": symlink_rejected}))
`);
    expect(result).toEqual({
      valid: true,
      unsafeFile: true,
      unsafeDirectory: true,
      symlinkRejected: true,
    });
  });
  it("classifies pre-launch failure and ambiguous post-launch failure", async () => {
    const result = await runPythonJson(`
import json, tempfile
from pathlib import Path
def fail_to_start(*_args, **_kwargs): raise OSError("private launch detail")
try: m.send_mail("sender@example.invalid", "recipient@example.invalid", b"test", popen=fail_to_start)
except m.MailSubmissionError as exc: launch_failure_is_known = not exc.outcome_uncertain
else: launch_failure_is_known = False
with tempfile.TemporaryDirectory() as tmp:
    nonzero = Path(tmp) / "nonzero-sendmail"
    nonzero.write_text(chr(10).join(["#!/usr/bin/python3", "raise SystemExit(1)", ""]))
    nonzero.chmod(0o700)
    try: m.send_mail("sender@example.invalid", "recipient@example.invalid", b"test", executable=str(nonzero), timeout_seconds=2)
    except m.MailSubmissionError as exc: launched_failure_is_uncertain = exc.outcome_uncertain
    else: launched_failure_is_uncertain = False
print(json.dumps({
    "launchFailureIsKnown": launch_failure_is_known,
    "launchedFailureIsUncertain": launched_failure_is_uncertain,
}))
`);
    expect(result["launchFailureIsKnown"]).toBe(true);
    expect(result["launchedFailureIsUncertain"]).toBe(true);
  });

  
  it("kills and reaps the entire sendmail process group on timeout", async () => {
    const result = await runPythonJson(`
import ctypes, json, os, signal, tempfile, time
from pathlib import Path
with tempfile.TemporaryDirectory() as tmp:
    parent_file = Path(tmp) / "parent.pid"
    child_file = Path(tmp) / "child.pid"
    executable = Path(tmp) / "fake-sendmail"
    script = chr(10).join([
        "#!/usr/bin/python3",
        "import os,time",
        "parent_file = " + repr(str(parent_file)),
        "child_file = " + repr(str(child_file)),
        "with open(parent_file, 'w') as output: output.write(str(os.getpid()))",
        "child = os.fork()",
        "if child == 0:",
        "    with open(child_file, 'w') as output: output.write(str(os.getpid()))",
        "    time.sleep(30)",
        "    os._exit(0)",
        "time.sleep(30)",
        "",
    ])
    executable.write_text(script)
    executable.chmod(0o700)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0: raise RuntimeError("could not enable test subreaper")
    try:
        m.send_mail("sender@example.com", "recipient@example.com", b"test", executable=str(executable), timeout_seconds=10, deadline_monotonic=time.monotonic() + 0.4)
    except m.MailSubmissionError as exc:
        timed_out = exc.outcome_uncertain
    else:
        timed_out = False
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not (parent_file.exists() and child_file.exists()):
        time.sleep(0.01)
    parent_pid = int(parent_file.read_text())
    child_pid = int(child_file.read_text())
    child_reaped = False
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            waited, _status = os.waitpid(child_pid, os.WNOHANG)
            if waited == child_pid:
                child_reaped = True
                break
        except ChildProcessError:
            child_reaped = True
            break
        time.sleep(0.01)
    try:
        os.kill(parent_pid, 0)
        parent_gone = False
    except ProcessLookupError:
        parent_gone = True
    if not child_reaped:
        try: os.killpg(parent_pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try: os.waitpid(child_pid, 0)
        except ChildProcessError: pass
    print(json.dumps({"timedOut": timed_out, "parentGone": parent_gone, "childReaped": child_reaped}))
`);
    expect(result).toEqual({ timedOut: true, parentGone: true, childReaped: true });
  });
  
  it("fails fast on overlapping runs and does not probe or deliver", async () => {
    const result = await runPythonJson(`
import json, tempfile
from pathlib import Path
${configSource}
with tempfile.TemporaryDirectory() as tmp:
    state_dir = Path(tmp) / "state"
    observed = []
    def health_probe(_url): observed.append("health"); return True
    def disk_probe(): observed.append("disk"); return 20.0
    def sendmail(*_args): observed.append("mail")
    try:
        with m.state_lock(state_dir):
            try:
                m.run_once(cfg, state_directory=state_dir, health_probe=health_probe, disk_probe=disk_probe, mail_sender=sendmail)
            except m.MonitorError as exc:
                busy = exc.exit_code == 75
            else:
                busy = False
    except m.MonitorError:
        busy = False
    print(json.dumps({
        "busy": busy,
        "observed": observed,
        "directoryMode": state_dir.stat().st_mode & 0o777,
        "lockMode": (state_dir / m.LOCK_FILE_NAME).stat().st_mode & 0o777,
        "stateExists": (state_dir / m.STATE_FILE_NAME).exists(),
    }))
`);
    expect(result).toEqual({
      busy: true,
      observed: [],
      directoryMode: 0o700,
      lockMode: 0o600,
      stateExists: false,
    });
  });
});

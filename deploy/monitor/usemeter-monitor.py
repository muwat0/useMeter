#!/usr/bin/python3
"""Bounded, host-local useMeter health and disk notification monitor."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import email.utils
import fcntl
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import http.client
import urllib.request
import signal
import uuid
from pathlib import Path
from typing import Callable, Iterator, Mapping
import threading
from urllib.parse import urlsplit


SERVICE_URL = "https://usemeter.example.com"
DEFAULT_HEALTH_URL = "http://127.0.0.1:3100/health"
HEALTH_TIMEOUT_SECONDS = 5
SENDMAIL_TIMEOUT_SECONDS = 10
ALERT_COOLDOWN_SECONDS = 600
DISK_ALERT_PERCENT = 90.0
MAX_HEALTH_BODY_BYTES = 4096
MAX_CONFIG_BYTES = 4096
MAX_STATE_BYTES = 8192
ALERT_COOLDOWN_MS = ALERT_COOLDOWN_SECONDS * 1000
SENDMAIL_TIMEOUT_MS = SENDMAIL_TIMEOUT_SECONDS * 1000
STATE_ADMISSION_BUDGET_SECONDS = 5
STATE_ADMISSION_BUDGET_MS = STATE_ADMISSION_BUDGET_SECONDS * 1000
SENDMAIL_PATH = "/usr/sbin/sendmail"
STATE_DIR = Path.home() / ".local" / "state" / "usemeter-monitor"
CONFIG_DIR = Path.home() / ".config" / "usemeter"
CONFIG_FILE = CONFIG_DIR / "monitor.env"
STATE_FILE_NAME = "state.json"
LOCK_FILE_NAME = "monitor.lock"
APPROVED_TEST_SUBJECT = "[useMeter ops] Delivery test"
APPROVED_TEST_BODY = (
    "This is the approved useMeter operational alert delivery test.\n"
    "Service: https://usemeter.example.com\n"
    "No account, credential, or usage data is included.\n"
)

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)
CONFIG_KEYS = {
    "USEMETER_MONITOR_ENABLED",
    "USEMETER_MONITOR_HEALTH_URL",
    "USEMETER_MONITOR_RECIPIENT",
    "USEMETER_MONITOR_SENDER",
}


class MonitorError(Exception):
    """Expected fail-closed monitor error with a safe operator-facing message."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class MailSubmissionError(MonitorError):
    def __init__(self, message: str, *, outcome_uncertain: bool) -> None:
        super().__init__(message)
        self.outcome_uncertain = outcome_uncertain


@dataclasses.dataclass(frozen=True)
class Config:
    enabled: bool
    health_url: str
    recipient: str | None
    sender: str | None


@dataclasses.dataclass(frozen=True)
class Observation:
    health_healthy: bool
    disk_used_percent: float
    active_alerts: tuple[str, ...]


def _validate_health_url(raw: str) -> str:
    if not isinstance(raw, str) or not raw or any(ord(ch) < 33 or ord(ch) == 127 for ch in raw):
        raise MonitorError("health URL configuration is invalid")
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise MonitorError("health URL configuration is invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or "?" in raw
        or "#" in raw
        or parsed.path != "/health"
    ):
        raise MonitorError(
            "health URL must be an HTTP(S) /health URL without userinfo, query, or fragment"
        )
    if port is not None and not 1 <= port <= 65535:
        raise MonitorError("health URL configuration is invalid")
    try:
        ip = ipaddress.ip_address(hostname)
        is_loopback = ip.is_loopback
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            raise MonitorError("health URL configuration is invalid") from None
        if not ascii_hostname or not HOSTNAME_RE.fullmatch(ascii_hostname):
            raise MonitorError("health URL configuration is invalid")
        is_loopback = ascii_hostname.lower() == "localhost"
    if parsed.scheme == "http" and not is_loopback:
        raise MonitorError("plain HTTP health URLs are limited to loopback")
    return raw


def _validate_email(raw: str, field: str) -> str:
    if (
        not isinstance(raw, str)
        or len(raw) > 254
        or not EMAIL_RE.fullmatch(raw)
        or "\r" in raw
        or "\n" in raw
    ):
        raise MonitorError(f"{field} address configuration is invalid")
    local, domain = raw.rsplit("@", 1)
    if (
        len(local) > 64
        or local.startswith(("-", "."))
        or local.endswith(".")
        or ".." in local
        or any(len(label) > 63 for label in domain.split("."))
    ):
        raise MonitorError(f"{field} address configuration is invalid")
    return raw


def config_from_values(values: Mapping[str, str]) -> Config:
    enabled_value = values.get("USEMETER_MONITOR_ENABLED", "0")
    if enabled_value not in {"0", "1"}:
        raise MonitorError("monitor enable setting must be 0 or 1")
    health_url = _validate_health_url(
        values.get("USEMETER_MONITOR_HEALTH_URL", DEFAULT_HEALTH_URL)
    )
    raw_recipient = values.get("USEMETER_MONITOR_RECIPIENT", "")
    raw_sender = values.get("USEMETER_MONITOR_SENDER", "")
    if bool(raw_recipient) != bool(raw_sender):
        raise MonitorError("recipient and sender must both be configured")
    recipient = _validate_email(raw_recipient, "recipient") if raw_recipient else None
    sender = _validate_email(raw_sender, "sender") if raw_sender else None
    enabled = enabled_value == "1"
    if enabled and (recipient is None or sender is None):
        raise MonitorError("automatic delivery requires both recipient and sender")
    return Config(enabled, health_url, recipient, sender)


def _safe_directory(path: Path, *, create: bool) -> None:
    try:
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
    except OSError:
        raise MonitorError("private monitor directory is unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise MonitorError("private monitor directory is unsafe")


def _open_private_file(path: Path, flags: int, mode: int = 0o600) -> int:
    try:
        fd = os.open(
            path,
            flags
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            mode,
        )
        info = os.fstat(fd)
    except OSError:
        raise MonitorError("private monitor file is unavailable or unsafe") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(fd)
        raise MonitorError("private monitor file is unsafe")
    return fd


def read_config_file(path: Path = CONFIG_FILE) -> dict[str, str]:
    """Read the strict KEY=value file without shell evaluation or value logging."""
    directory = path.parent
    try:
        directory_info = directory.lstat()
    except FileNotFoundError:
        return {}
    except OSError:
        raise MonitorError("monitor configuration directory is unavailable") from None
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != os.getuid()
        or stat.S_IMODE(directory_info.st_mode) != 0o700
    ):
        raise MonitorError("monitor configuration directory is unsafe")
    try:
        fd = _open_private_file(path, os.O_RDONLY)
    except MonitorError as exc:
        try:
            path.lstat()
        except FileNotFoundError:
            return {}
        except OSError:
            pass
        raise exc
    try:
        with os.fdopen(fd, "rb", closefd=True) as config_file:
            raw = config_file.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise MonitorError("monitor configuration cannot be read") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise MonitorError("monitor configuration is too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise MonitorError("monitor configuration is invalid") from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in CONFIG_KEYS or key in values or "\x00" in value:
            raise MonitorError("monitor configuration is invalid")
        values[key] = value
    return values


def load_config(environ: Mapping[str, str] | None = None) -> Config:
    values = read_config_file()
    source = os.environ if environ is None else environ
    for key in CONFIG_KEYS:
        if key in source:
            values[key] = source[key]
    return config_from_values(values)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HealthDeadlineExceeded(Exception):
    pass


@contextlib.contextmanager
def _health_deadline(timeout_seconds: float) -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        raise _HealthDeadlineExceeded()
    try:
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        previous_handler = signal.getsignal(signal.SIGALRM)
    except (AttributeError, OSError, ValueError):
        raise _HealthDeadlineExceeded() from None
    if previous_timer != (0.0, 0.0):
        raise _HealthDeadlineExceeded()

    def expire(_signum, _frame):
        raise _HealthDeadlineExceeded()

    signal.signal(signal.SIGALRM, expire)
    try:
        signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous_handler)


def probe_health(health_url: str, *, timeout_seconds: float = HEALTH_TIMEOUT_SECONDS) -> bool:
    """Return only whether the bounded public health response is exactly healthy."""
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        return False
    request = urllib.request.Request(
        health_url,
        headers={"Accept": "application/json", "User-Agent": "usemeter-host-monitor/1"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
    )
    try:
        with _health_deadline(float(timeout_seconds)):
            with opener.open(request, timeout=timeout_seconds) as response:
                if response.status != 200:
                    return False
                if response.headers.get_all("Transfer-Encoding"):
                    return False
                content_lengths = response.headers.get_all("Content-Length", [])
                if len(content_lengths) > 1:
                    return False
                if content_lengths:
                    raw_length = content_lengths[0].strip()
                    if not raw_length.isascii() or not raw_length.isdigit():
                        return False
                    if int(raw_length) > MAX_HEALTH_BODY_BYTES:
                        return False
                body = response.read(MAX_HEALTH_BODY_BYTES + 1)
            if len(body) > MAX_HEALTH_BODY_BYTES:
                return False
            payload = json.loads(body.decode("utf-8"))
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        TimeoutError,
        OSError,
        ValueError,
        UnicodeError,
        RecursionError,
        _HealthDeadlineExceeded,
    ):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("status") == "ok"
        and payload.get("integrity") is True
        and payload.get("pollerRunning") is True
    )


def measure_disk_used_percent() -> float:
    """Use statvfs available blocks on the monitor user's root-mounted home."""
    try:
        values = os.statvfs(Path.home())
    except OSError:
        raise MonitorError("host filesystem measurement failed") from None
    total_blocks = values.f_blocks
    available_blocks = values.f_bavail
    if total_blocks <= 0 or available_blocks < 0 or available_blocks > total_blocks:
        raise MonitorError("host filesystem measurement failed")
    return (total_blocks - available_blocks) * 100.0 / total_blocks


def collect_observation(
    health_url: str,
    *,
    health_probe: Callable[[str], bool] = probe_health,
    disk_probe: Callable[[], float] = measure_disk_used_percent,
) -> Observation:
    health_healthy = health_probe(health_url)
    if type(health_healthy) is not bool:
        raise MonitorError("health observation is invalid")
    disk_used_percent = disk_probe()
    if (
        isinstance(disk_used_percent, bool)
        or not isinstance(disk_used_percent, (int, float))
        or not math.isfinite(disk_used_percent)
        or not 0.0 <= disk_used_percent <= 100.0
    ):
        raise MonitorError("host filesystem measurement failed")
    alerts: list[str] = []
    if disk_used_percent >= DISK_ALERT_PERCENT:
        alerts.append("disk")
    if not health_healthy:
        alerts.append("health")
    return Observation(health_healthy, float(disk_used_percent), tuple(alerts))


@contextlib.contextmanager
def state_lock(state_directory: Path) -> Iterator[None]:
    _safe_directory(state_directory, create=True)
    lock_path = state_directory / LOCK_FILE_NAME
    fd = _open_private_file(lock_path, os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MonitorError("another monitor run is already in progress", 75) from None
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _empty_state() -> dict[str, object]:
    return {
        "version": 1,
        "submitted_alerts": [],
        "last_submitted_at_ms": None,
        "last_attempt_at_ms": None,
        "pending_retry_at_ms": None,
        "submission_pending": False,
    }


def _load_state(state_directory: Path) -> dict[str, object]:
    state_path = state_directory / STATE_FILE_NAME
    try:
        fd = _open_private_file(state_path, os.O_RDONLY)
    except MonitorError as exc:
        try:
            state_path.lstat()
        except FileNotFoundError:
            return _empty_state()
        except OSError:
            pass
        raise exc
    try:
        with os.fdopen(fd, "rb", closefd=True) as state_file:
            raw = state_file.read(MAX_STATE_BYTES + 1)
    except OSError:
        raise MonitorError("monitor state cannot be read") from None
    if len(raw) > MAX_STATE_BYTES:
        raise MonitorError("monitor state is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MonitorError("monitor state is invalid") from None
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "version",
            "submitted_alerts",
            "last_submitted_at_ms",
            "last_attempt_at_ms",
            "pending_retry_at_ms",
            "submission_pending",
        }
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["submitted_alerts"], list)
        or any(
            type(alert) is not str or alert not in {"disk", "health"}
            for alert in value["submitted_alerts"]
        )
        or len(set(value["submitted_alerts"])) != len(value["submitted_alerts"])
        or value["submitted_alerts"] != sorted(value["submitted_alerts"])
        or type(value["submission_pending"]) is not bool
        or any(
            value[key] is not None
            and (type(value[key]) is not int or value[key] < 0)
            for key in (
                "last_submitted_at_ms",
                "last_attempt_at_ms",
                "pending_retry_at_ms",
            )
        )
        or (value["submitted_alerts"] and value["last_submitted_at_ms"] is None)
        or (
            value["last_submitted_at_ms"] is not None
            and value["last_attempt_at_ms"] is None
        )
        or (value["submission_pending"] and value["last_attempt_at_ms"] is None)
        or (
            value["submission_pending"]
            and value["pending_retry_at_ms"] is None
        )
        or (
            value["submission_pending"]
            and value["pending_retry_at_ms"] < value["last_attempt_at_ms"]
        )
        or (
            not value["submission_pending"]
            and value["pending_retry_at_ms"] is not None
        )
    ):
        raise MonitorError("monitor state is invalid")
    return value


def _save_state(state_directory: Path, state: dict[str, object]) -> None:
    state_path = state_directory / STATE_FILE_NAME
    raw = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temp_path: str | None = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".state-", dir=state_directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as state_file:
            state_file.write(raw)
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(temp_path, state_path)
        temp_path = None
        directory_fd = os.open(
            state_directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise MonitorError("monitor state could not be safely persisted") from None
    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _mail_message(sender: str, recipient: str, subject: str, body: str) -> bytes:
    _validate_email(sender, "sender")
    _validate_email(recipient, "recipient")
    if any(ch in subject for ch in "\r\n") or "\r" in body or not body.endswith("\n"):
        raise MonitorError("mail content is invalid")
    message_id = f"<{uuid.uuid4()}@usemeter.example.com>"
    headers = [
        f"Date: {email.utils.formatdate(time.time(), localtime=False, usegmt=True)}",
        f"Message-ID: {message_id}",
        f"From: {sender}",
        f"To: {recipient}",
        f"Subject: {subject}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8",
        "Content-Transfer-Encoding: 8bit",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("utf-8")


def _terminate_mail_process_group(process: subprocess.Popen[bytes]) -> None:
    group_kill_failed = False
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        group_kill_failed = True
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            raise MonitorError("local mail helper cleanup failed") from None
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.communicate(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            raise MonitorError("local mail helper cleanup failed") from None
    except OSError:
        raise MonitorError("local mail helper cleanup failed") from None
    if group_kill_failed:
        raise MonitorError("local mail helper cleanup failed")

def send_mail(
    sender: str,
    recipient: str,
    message: bytes,
    *,
    executable: str = SENDMAIL_PATH,
    timeout_seconds: float = SENDMAIL_TIMEOUT_SECONDS,
    deadline_monotonic: float | None = None,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> None:
    """Submit one RFC 5322 message through the fixed local sendmail interface."""
    _validate_email(sender, "sender")
    _validate_email(recipient, "recipient")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise MonitorError("mail submission timeout configuration is invalid")
    started = time.monotonic()
    deadline = started + timeout_seconds
    if deadline_monotonic is not None:
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(deadline_monotonic)
        ):
            raise MonitorError("mail submission deadline is invalid")
        deadline = min(deadline, float(deadline_monotonic))
    if deadline <= started:
        raise MailSubmissionError("local mail submission deadline expired", outcome_uncertain=False)

    argv = [executable, "-oi", "-f", sender, "--", recipient]
    try:
        process = popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            start_new_session=True,
        )
    except OSError:
        raise MailSubmissionError("local mail submission failed", outcome_uncertain=False) from None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        try:
            _terminate_mail_process_group(process)
        except MonitorError:
            raise MailSubmissionError(
                "local mail submission deadline expired; helper cleanup was incomplete",
                outcome_uncertain=True,
            ) from None
        raise MailSubmissionError("local mail submission deadline expired", outcome_uncertain=True) from None
    try:
        process.communicate(input=message, timeout=remaining)
    except subprocess.TimeoutExpired:
        try:
            _terminate_mail_process_group(process)
        except MonitorError:
            raise MailSubmissionError(
                "local mail submission timed out; helper cleanup was incomplete",
                outcome_uncertain=True,
            ) from None
        raise MailSubmissionError("local mail submission timed out", outcome_uncertain=True) from None
    except OSError:
        try:
            _terminate_mail_process_group(process)
        except MonitorError:
            pass
        raise MailSubmissionError("local mail submission failed", outcome_uncertain=True) from None
    if process.returncode != 0:
        _terminate_mail_process_group(process)
        raise MailSubmissionError("local mail submission failed", outcome_uncertain=True)


def _automatic_body(observation: Observation) -> str:
    disk_status = "ALERT" if observation.disk_used_percent >= DISK_ALERT_PERCENT else "OK"
    health_status = "healthy" if observation.health_healthy else "unhealthy"
    return (
        "useMeter operational status changed.\n"
        f"Service: {SERVICE_URL}\n"
        f"Disk status: {disk_status} ({observation.disk_used_percent:.1f}%; threshold 90%).\n"
        f"Health status: {health_status}.\n"
    )


def _epoch_milliseconds(
    now_fn: Callable[[], float],
    *,
    round_up: bool = False,
) -> int:
    value = now_fn()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MonitorError("system clock is invalid")
    try:
        seconds = float(value)
        milliseconds = seconds * 1000.0
        if not math.isfinite(seconds) or seconds < 0 or not math.isfinite(milliseconds):
            raise MonitorError("system clock is invalid")
        return math.ceil(milliseconds) if round_up else math.floor(milliseconds)
    except (OverflowError, ValueError):
        raise MonitorError("system clock is invalid") from None


def _monotonic_seconds(monotonic_fn: Callable[[], float]) -> float:
    value = monotonic_fn()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MonitorError("monotonic clock is invalid")
    result = float(value)
    if not math.isfinite(result):
        raise MonitorError("monotonic clock is invalid")
    return result


def _cooldown_remaining_ms(state: Mapping[str, object], now_ms: int) -> int:
    deadlines: list[int] = []
    last_submitted_at = state["last_submitted_at_ms"]
    if last_submitted_at is not None:
        deadlines.append(int(last_submitted_at) + ALERT_COOLDOWN_MS)
    last_attempt_at = state["last_attempt_at_ms"]
    if state["submission_pending"]:
        deadlines.append(int(state["pending_retry_at_ms"]))
    elif last_attempt_at is not None:
        deadlines.append(int(last_attempt_at) + ALERT_COOLDOWN_MS)
    return max(0, max(deadlines, default=now_ms) - now_ms)


def _result(
    mode: str,
    config: Config,
    observation: Observation,
    would_notify: bool,
    cooldown_remaining: int,
) -> dict[str, object]:
    return {
        "mode": mode,
        "deliveryEnabled": config.enabled,
        "healthHealthy": observation.health_healthy,
        "diskUsagePercent": round(observation.disk_used_percent, 1),
        "activeAlerts": list(observation.active_alerts),
        "wouldNotify": would_notify,
        "cooldownRemainingSeconds": cooldown_remaining,
    }


def run_once(
    config: Config,
    *,
    state_directory: Path = STATE_DIR,
    now_fn: Callable[[], float] = time.time,
    monotonic_fn: Callable[[], float] = time.monotonic,
    health_probe: Callable[[str], bool] = probe_health,
    disk_probe: Callable[[], float] = measure_disk_used_percent,
    mail_sender: Callable[[str, str, bytes], None] | None = None,
    check_only: bool = False,
    send_test: bool = False,
) -> dict[str, object]:
    if check_only and send_test:
        raise MonitorError("check-only and send-test cannot be combined")
    with state_lock(state_directory):
        if send_test:
            if config.recipient is None or config.sender is None:
                raise MonitorError("send-test requires configured recipient and sender")
            message = _mail_message(
                config.sender,
                config.recipient,
                APPROVED_TEST_SUBJECT,
                APPROVED_TEST_BODY,
            )
            if mail_sender is None:
                send_mail(config.sender, config.recipient, message)
            else:
                mail_sender(config.sender, config.recipient, message)
            return {"mode": "send-test", "submissionAccepted": True}

        observation = collect_observation(
            config.health_url,
            health_probe=health_probe,
            disk_probe=disk_probe,
        )
        state = _load_state(state_directory)
        now_ms = _epoch_milliseconds(now_fn)
        changed = (
            list(observation.active_alerts) != state["submitted_alerts"]
            or state["submission_pending"]
        )
        would_notify = config.enabled and changed
        cooldown_remaining_ms = _cooldown_remaining_ms(state, now_ms)
        result = _result(
            "check-only" if check_only else "monitor",
            config,
            observation,
            would_notify,
            (cooldown_remaining_ms + 999) // 1000 if would_notify else 0,
        )
        if check_only or not config.enabled or not changed or cooldown_remaining_ms > 0:
            return result

        if config.recipient is None or config.sender is None:
            raise MonitorError("automatic delivery requires both recipient and sender")
        subject = "[useMeter ops] Operational alert" if observation.active_alerts else "[useMeter ops] Operational recovery"
        message = _mail_message(
            config.sender,
            config.recipient,
            subject,
            _automatic_body(observation),
        )

        admission_started = _monotonic_seconds(monotonic_fn)
        attempt_at_ms = _epoch_milliseconds(now_fn, round_up=True)
        admission_state = dict(state)
        admission_state["last_attempt_at_ms"] = attempt_at_ms
        admission_state["pending_retry_at_ms"] = (
            attempt_at_ms
            + ALERT_COOLDOWN_MS
            + STATE_ADMISSION_BUDGET_MS
            + SENDMAIL_TIMEOUT_MS
        )
        admission_state["submission_pending"] = True
        _save_state(state_directory, admission_state)
        admission_elapsed_ms = math.ceil(
            (_monotonic_seconds(monotonic_fn) - admission_started) * 1000.0
        )
        admission_finished_ms = _epoch_milliseconds(now_fn)
        admission_deadline_monotonic = (
            admission_started
            + STATE_ADMISSION_BUDGET_SECONDS
            + SENDMAIL_TIMEOUT_SECONDS
        )
        remaining_send_timeout = (
            admission_deadline_monotonic - _monotonic_seconds(monotonic_fn)
        )
        if (
            admission_elapsed_ms < 0
            or admission_elapsed_ms > STATE_ADMISSION_BUDGET_MS
            or admission_finished_ms >= attempt_at_ms + STATE_ADMISSION_BUDGET_MS
            or remaining_send_timeout <= 0
        ):
            raise MonitorError("monitor state admission exceeded its bounded window")
        try:
            if mail_sender is None:
                send_mail(
                    config.sender,
                    config.recipient,
                    message,
                    timeout_seconds=min(SENDMAIL_TIMEOUT_SECONDS, remaining_send_timeout),
                    deadline_monotonic=admission_deadline_monotonic,
                )
            else:
                mail_sender(config.sender, config.recipient, message)
        except MailSubmissionError as exc:
            if not exc.outcome_uncertain:
                failed_state = dict(admission_state)
                failed_state["submission_pending"] = False
                failed_state["pending_retry_at_ms"] = None
                try:
                    _save_state(state_directory, failed_state)
                except MonitorError:
                    pass
            raise

        submitted_at_ms = _epoch_milliseconds(now_fn, round_up=True)
        submitted_state = {
            "version": 1,
            "submitted_alerts": list(observation.active_alerts),
            "last_submitted_at_ms": submitted_at_ms,
            "last_attempt_at_ms": attempt_at_ms,
            "pending_retry_at_ms": None,
            "submission_pending": False,
        }
        _save_state(state_directory, submitted_state)
        result["cooldownRemainingSeconds"] = ALERT_COOLDOWN_SECONDS
        result["wouldNotify"] = False
        result["submissionAccepted"] = True
        return result



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded host-local useMeter health and disk monitor")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-only", action="store_true", help="observe and report without sending or advancing state")
    mode.add_argument("--send-test", action="store_true", help="send the fixed approved delivery-test message once")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = load_config()
        result = run_once(config, check_only=args.check_only, send_test=args.send_test)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except MonitorError as exc:
        print(f"useMeter monitor: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception:
        print("useMeter monitor: unexpected local monitor failure", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

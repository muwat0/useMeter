#!/usr/bin/env python3
"""
useMeter Password Reset Mail Bridge
====================================
Local unprivileged Unix domain socket bridge that receives password reset
requests from the useMeter Docker container and invokes the host sendmail
binary (/usr/sbin/sendmail) to deliver emails.

Security & Operational Invariants:
1. Rootless & Unprivileged: Runs as the host user under systemd --user.
2. Least Privilege: No network listener, no SMTP credentials, no shell execution.
3. Strict Schema: Accepts ONLY {"recipient": "<email>", "token": "<64-hex>"}.
4. No Injections: Headers and body are strictly templated; arguments use '--'.
5. Peer Credentials: Validates SO_PEERCRED to restrict caller UID.
6. Persistent Directory: Parent directory (0770, group-owned) is never unlinked.
   Socket file (0660) is recreated on startup. Only stale Sockets are unlinked.
7. Zero Secret Logging: Tokens, recipients, and sendmail stderr are NEVER logged.
8. Subprocess Hygiene: Process groups are tracked and reaped on timeout/cancellation.
9. Disconnect & Coalescing: Client disconnect reaps child; trailing bytes rejected.
"""

from __future__ import annotations

import argparse
import asyncio
import email.utils
import json
import logging
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
import urllib.parse
import uuid
from typing import Set

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("usemeter-mail-bridge")

# Strict regex patterns
RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
RE_TOKEN = re.compile(r"^[0-9a-f]{64}$")
RE_HOSTNAME = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Linux SO_PEERCRED constant
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)


def validate_public_origin(origin: str) -> str:
    if not isinstance(origin, str):
        raise ValueError("public_origin must be a string")
    if any(ord(c) <= 32 or ord(c) == 127 for c in origin) or "\\" in origin:
        raise ValueError("public_origin contains invalid whitespace, backslash, or control characters")
    if not origin.startswith("https://"):
        raise ValueError("public_origin must start with 'https://'")
    if "@" in origin or "?" in origin or "#" in origin:
        raise ValueError("public_origin must not contain '@', '?', or '#'")

    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https":
        raise ValueError("public_origin scheme must be https")
    if parsed.username or parsed.password:
        raise ValueError("public_origin must not contain username or password")
    if not parsed.hostname:
        raise ValueError("public_origin must have a valid hostname")
    if not RE_HOSTNAME.match(parsed.hostname):
        raise ValueError("public_origin hostname format is invalid")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("public_origin must not contain path, query, or fragment")

    port_part = f":{parsed.port}" if parsed.port is not None else ""
    canonical = f"https://{parsed.hostname.lower()}{port_part}"
    if canonical != origin.lower():
        raise ValueError(
            "public_origin must be canonical https://hostname[:port] without trailing characters"
        )
    return canonical


def validate_email_address(addr: str, field_name: str = "email") -> str:
    if not isinstance(addr, str):
        raise ValueError(f"{field_name} must be a string")
    if any(ord(c) <= 32 or ord(c) == 127 for c in addr) or "\r" in addr or "\n" in addr or "\0" in addr:
        raise ValueError(f"{field_name} contains prohibited whitespace or control characters")
    if addr.startswith("-"):
        raise ValueError(f"{field_name} must not start with '-'")
    if len(addr) > 254:
        raise ValueError(f"{field_name} length must not exceed 254 characters")
    if not RE_EMAIL.match(addr):
        raise ValueError(f"{field_name} is not a valid email address format")
    return addr


def validate_token(token: str) -> str:
    if not isinstance(token, str):
        raise ValueError("token must be a string")
    if len(token) != 64 or not RE_TOKEN.fullmatch(token):
        raise ValueError("token must be exactly 64 lowercase hexadecimal characters")
    return token


def parse_allowed_uids(raw: str | None) -> Set[int]:
    if raw is None or raw.strip() == "":
        return {1000, os.geteuid()}

    uids: Set[int] = set()
    for item in raw.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        if not cleaned.isdigit():
            raise ValueError(f"Invalid UID in allowed_uids: '{cleaned}' is not an integer")
        uid_val = int(cleaned)
        if uid_val < 0:
            raise ValueError(f"Invalid UID in allowed_uids: '{cleaned}' must be non-negative")
        uids.add(uid_val)

    if not uids:
        raise ValueError("allowed_uids was specified but contained no valid UIDs")
    return uids


def check_peer_creds(sock: socket.socket, allowed_uids: Set[int]) -> bool:
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        if uid not in allowed_uids:
            logger.warning("Rejected connection from unauthorized peer UID: %d (PID: %d)", uid, pid)
            return False
        return True
    except Exception as exc:
        logger.warning("Failed to inspect peer credentials: %s", type(exc).__name__)
        return False


def build_mail_rfc5322(sender: str, recipient: str, token: str, public_origin: str) -> bytes:
    reset_url = f"{public_origin}/reset-password#token={token}"
    date_hdr = email.utils.formatdate(localtime=False)
    domain = sender.split("@", 1)[1] if "@" in sender else "localhost"
    msg_id = f"<{uuid.uuid4().hex}@{domain}>"

    headers = [
        f"From: useMeter <{sender}>",
        f"To: <{recipient}>",
        "Subject: Reset your useMeter password",
        f"Date: {date_hdr}",
        f"Message-ID: {msg_id}",
        "Auto-Submitted: auto-generated",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 8bit",
    ]

    body = (
        "Hello,\n\n"
        "A password reset was requested for your useMeter account.\n\n"
        "To reset your password, visit the link below:\n"
        f"{reset_url}\n\n"
        "This link is valid for 15 minutes. If you did not request this, you can safely ignore this email.\n"
    )

    message = "\r\n".join(headers) + "\r\n\r\n" + body
    return message.encode("utf-8")


class MailBridgeServer:
    def __init__(
        self,
        socket_path: str,
        public_origin: str,
        sender: str,
        sendmail_bin: str = "/usr/sbin/sendmail",
        allowed_uids: Set[int] | None = None,
        group_id: int | None = None,
        max_concurrency: int = 5,
        read_timeout: float = 5.0,
        submission_timeout: float = 10.0,
    ):
        self.socket_path = os.path.abspath(socket_path)
        self.socket_dir = os.path.dirname(self.socket_path)
        self.public_origin = validate_public_origin(public_origin)
        self.sender = validate_email_address(sender, "sender")
        self.sendmail_bin = sendmail_bin
        self.allowed_uids = allowed_uids if allowed_uids is not None else {1000, os.geteuid()}
        self.group_id = group_id
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.read_timeout = read_timeout
        self.submission_timeout = submission_timeout
        self.server: asyncio.Server | None = None
        self.active_tasks: Set[asyncio.Task] = set()

    def ensure_directory(self) -> None:
        if not os.path.exists(self.socket_dir):
            os.makedirs(self.socket_dir, mode=0o770, exist_ok=False)
            logger.info("Created directory %s with mode 0770", self.socket_dir)
        elif not os.path.isdir(self.socket_dir) or os.path.islink(self.socket_dir):
            raise RuntimeError(f"Configured socket directory {self.socket_dir} is not a valid directory")

        os.chmod(self.socket_dir, 0o770)
        if self.group_id is not None:
            try:
                os.chown(self.socket_dir, -1, self.group_id)
            except PermissionError as exc:
                raise PermissionError(
                    f"Cannot chown directory {self.socket_dir} to group {self.group_id}: {exc}"
                ) from exc

        st = os.stat(self.socket_dir)
        if st.st_uid != os.geteuid():
            raise RuntimeError(
                f"Security check failed: directory owner UID {st.st_uid} != current UID {os.geteuid()}"
            )
        if self.group_id is not None and st.st_gid != self.group_id:
            raise RuntimeError(
                f"Security check failed: directory GID {st.st_gid} != configured group {self.group_id}"
            )
        if stat.S_IMODE(st.st_mode) != 0o770:
            raise RuntimeError(
                f"Security check failed: directory permissions must be 0770, got {oct(stat.S_IMODE(st.st_mode))}"
            )

    async def submit_mail(
        self, recipient: str, token: str, abort_event: asyncio.Event | None = None
    ) -> bool:
        if abort_event is not None and abort_event.is_set():
            logger.warning("Peer aborted before process dispatch; zero subprocesses spawned")
            return False

        message_bytes = build_mail_rfc5322(self.sender, recipient, token, self.public_origin)

        cmd = [self.sendmail_bin, "-oi", "-f", self.sender, "--", recipient]
        try:
            # start_new_session=True creates a new process group for clean descendant reaping.
            # stdout and stderr use DEVNULL to avoid unbounded buffers, secret copies, and pipe hangs.
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
        except FileNotFoundError:
            logger.error("Sendmail binary not found at %s", self.sendmail_bin)
            return False
        except Exception as exc:
            logger.error("Failed to spawn sendmail process: %s", type(exc).__name__)
            return False
        pgid = proc.pid
        completed_successfully = False

        try:
            try:
                await asyncio.wait_for(
                    proc.communicate(input=message_bytes),
                    timeout=self.submission_timeout,
                )
                if proc.returncode == 0:
                    completed_successfully = True
            except asyncio.TimeoutError:
                logger.error("Sendmail submission timed out after %s seconds", self.submission_timeout)
                return False
        finally:
            # If not completed successfully (timed out, cancelled, or failed), terminate the whole process group
            if not completed_successfully:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await proc.wait()
                except Exception:
                    pass
        if proc.returncode != 0:
            logger.error("Sendmail submission failed with exit code %d", proc.returncode)
            # CRITICAL: NEVER log proc.stderr or recipient or token!
            return False

        logger.info("Sendmail submission completed successfully (exit code 0)")
        return True

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        curr_task = asyncio.current_task()
        if curr_task:
            self.active_tasks.add(curr_task)
            curr_task.add_done_callback(self.active_tasks.discard)

        try:
            sock = writer.get_extra_info("socket")
            if not check_peer_creds(sock, self.allowed_uids):
                writer.write(b'{"ok":false}\n')
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                return

            if self.semaphore.locked():
                logger.warning("Bridge busy: rejecting connection due to concurrency limit")
                writer.write(b'{"ok":false}\n')
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                return

            async with self.semaphore:
                try:
                    # Enforce bounded read (buffer limit 1024 bytes)
                    line = await asyncio.wait_for(reader.readline(), timeout=self.read_timeout)
                    if not line or not line.endswith(b"\n") or len(line) > 1024:
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                        return

                    # Verify that client half-closed (EOF expected) and no trailing data was sent
                    try:
                        trailing = await asyncio.wait_for(reader.read(1), timeout=0.5)
                        if trailing != b"":
                            logger.warning("Rejecting request with unexpected trailing data")
                            writer.write(b'{"ok":false}\n')
                            await asyncio.wait_for(writer.drain(), timeout=2.0)
                            return
                    except asyncio.TimeoutError:
                        logger.warning("Rejecting request: client did not half-close connection (missing EOF)")
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                        return

                    try:
                        payload = json.loads(line.decode("utf-8"))
                    except Exception:
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                        return

                    if not isinstance(payload, dict):
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                        return

                    if set(payload.keys()) != {"recipient", "token"}:
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                        return

                    try:
                        recipient = validate_email_address(payload["recipient"], "recipient")
                        token = validate_token(payload["token"])
                    except ValueError:
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                        return

                    sock = writer.get_extra_info("socket")
                    real_sock = getattr(sock, "_sock", sock)
                    abort_event = asyncio.Event()

                    async def watch_client_abort() -> None:
                        try:
                            fd = real_sock.fileno()
                            if fd < 0:
                                abort_event.set()
                                return
                            poll_obj = select.poll()
                            poll_obj.register(fd, select.POLLHUP | select.POLLERR)
                            for _, event in poll_obj.poll(0):
                                if event & (select.POLLHUP | select.POLLERR):
                                    abort_event.set()
                                    return
                            while not abort_event.is_set():
                                await asyncio.sleep(0.01)
                                for _, event in poll_obj.poll(0):
                                    if event & (select.POLLHUP | select.POLLERR):
                                        abort_event.set()
                                        return
                        except Exception:
                            abort_event.set()

                    watch_task = asyncio.create_task(watch_client_abort())
                    abort_wait_task = asyncio.create_task(abort_event.wait())
                    submit_task = asyncio.create_task(
                        self.submit_mail(recipient, token, abort_event=abort_event)
                    )
                    try:
                        done, pending = await asyncio.wait(
                            [submit_task, abort_wait_task],
                            return_when=asyncio.FIRST_COMPLETED,
                        )

                        if abort_event.is_set():
                            logger.warning(
                                "Peer destroyed socket while submission in progress; cancelling submission"
                            )
                            return

                        ok = submit_task.result()
                        writer.write(b'{"ok":true}\n' if ok else b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                    finally:
                        for t in (submit_task, watch_task, abort_wait_task):
                            if not t.done():
                                t.cancel()
                        await asyncio.gather(
                            submit_task, watch_task, abort_wait_task, return_exceptions=True
                        )
                except (asyncio.TimeoutError, asyncio.LimitOverrunError):
                    logger.warning("Client read timed out or exceeded buffer limit")
                    try:
                        writer.write(b'{"ok":false}\n')
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                    except Exception:
                        pass
        except Exception as exc:
            logger.error("Unhandled error in client handler: %s", type(exc).__name__)
            try:
                writer.write(b'{"ok":false}\n')
                await asyncio.wait_for(writer.drain(), timeout=2.0)
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass

    async def start(self) -> None:
        self.ensure_directory()

        if os.path.lexists(self.socket_path):
            lst = os.lstat(self.socket_path)
            if stat.S_ISSOCK(lst.st_mode):
                try:
                    os.unlink(self.socket_path)
                    logger.info("Unlinked stale socket file: %s", self.socket_path)
                except OSError as e:
                    raise RuntimeError(f"Failed to unlink stale socket file: {e}") from e
            else:
                raise RuntimeError(
                    f"Configured socket path {self.socket_path} exists and is not a socket file! Refusing to unlink."
                )

        # start_unix_server with limit=1024 limits StreamReader buffer size
        self.server = await asyncio.start_unix_server(
            self.handle_client,
            path=self.socket_path,
            limit=1024,
        )
        logger.info("Unix socket server listening at %s", self.socket_path)

        os.chmod(self.socket_path, 0o660)
        if self.group_id is not None:
            try:
                os.chown(self.socket_path, -1, self.group_id)
            except PermissionError as exc:
                raise PermissionError(
                    f"Cannot chown socket {self.socket_path} to group {self.group_id}: {exc}"
                ) from exc

        st = os.stat(self.socket_path)
        if st.st_uid != os.geteuid():
            raise RuntimeError(
                f"Security check failed: socket owner UID {st.st_uid} != current UID {os.geteuid()}"
            )
        if self.group_id is not None and st.st_gid != self.group_id:
            raise RuntimeError(
                f"Security check failed: socket GID {st.st_gid} != configured group {self.group_id}"
            )
        if stat.S_IMODE(st.st_mode) != 0o660:
            raise RuntimeError(
                f"Security check failed: socket permissions must be 0660, got {oct(stat.S_IMODE(st.st_mode))}"
            )

    async def stop(self) -> None:
        if self.server:
            self.server.close()

        if self.active_tasks:
            for t in list(self.active_tasks):
                t.cancel()
            await asyncio.gather(*self.active_tasks, return_exceptions=True)

        if self.server:
            await self.server.wait_closed()
            self.server = None
        if os.path.lexists(self.socket_path):
            lst = os.lstat(self.socket_path)
            if stat.S_ISSOCK(lst.st_mode):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass
        logger.info("Mail bridge stopped cleanly")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="useMeter Unix Socket Password Reset Mail Bridge")
    parser.add_argument(
        "--socket-path",
        default=os.environ.get("MAIL_BRIDGE_SOCKET_PATH", ""),
        help="Full path to Unix domain socket file (e.g. /opt/usemeter/mail/bridge.sock)",
    )
    parser.add_argument(
        "--socket-dir",
        default=os.environ.get("MAIL_BRIDGE_SOCKET_DIR", ""),
        help="Directory to place bridge.sock if socket-path is not specified",
    )
    parser.add_argument(
        "--public-origin",
        default=os.environ.get("PUBLIC_ORIGIN", ""),
        help="Canonical HTTPS public origin (e.g. https://usemeter.example.com)",
    )
    parser.add_argument(
        "--sender",
        default=os.environ.get("MAIL_SENDER", ""),
        help="Validated sender email address (e.g. usemeter@example.com)",
    )
    parser.add_argument(
        "--sendmail-bin",
        default=os.environ.get("SENDMAIL_BIN", "/usr/sbin/sendmail"),
        help="Path to sendmail binary (default: /usr/sbin/sendmail)",
    )
    parser.add_argument(
        "--allowed-uids",
        default=os.environ.get("ALLOWED_PEER_UIDS", None),
        help="Comma-separated allowed peer UIDs (default: 1000,current UID)",
    )
    parser.add_argument(
        "--group-id",
        type=int,
        default=int(os.environ.get("SOCKET_GROUP_ID")) if os.environ.get("SOCKET_GROUP_ID") else None,
        help="GID for socket and directory permissions (e.g. 1000)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()

    if not args.public_origin:
        raise ValueError("PUBLIC_ORIGIN is mandatory (via --public-origin or PUBLIC_ORIGIN env var)")
    if not args.sender:
        raise ValueError("MAIL_SENDER is mandatory (via --sender or MAIL_SENDER env var)")

    socket_path = args.socket_path
    if not socket_path:
        socket_dir = args.socket_dir or os.path.expanduser("~/.local/state/usemeter-mail")
        socket_path = os.path.join(socket_dir, "bridge.sock")

    allowed_uids = parse_allowed_uids(args.allowed_uids)

    bridge = MailBridgeServer(
        socket_path=socket_path,
        public_origin=args.public_origin,
        sender=args.sender,
        sendmail_bin=args.sendmail_bin,
        allowed_uids=allowed_uids,
        group_id=args.group_id,
    )

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    await bridge.start()
    await stop_event.wait()
    await bridge.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

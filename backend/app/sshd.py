"""Fake SSH server. Only SSH_PASSWORD opens a shell, everything else
fails, so failed logins are real. Sessions get a fake shell and are
recorded in asciicast format. Logins, commands and session boundaries
are published to the event bus.
"""

import logging
import os
import uuid
from pathlib import Path

import asyncssh

from app.asciicast import SessionRecorder
from app.bus import Broadcaster
from app.fakeshell import HOSTNAME, run_command
from app.ratelimit import SlidingWindowLimiter
from app.schemas import Event

logger = logging.getLogger("hive.sshd")

SENSOR_ID = os.environ.get("SENSOR_ID", "hive-dev")
SSH_PORT = int(os.environ.get("SSH_PORT", "2222"))
HOST_KEY_PATH = Path(os.environ.get("SSH_HOST_KEY_PATH", "/data/ssh_host_key"))

# the one password that works, with any username
SSH_PASSWORD = os.environ.get("SSH_PASSWORD", "adminpass")
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120"))

# shared across connections
_limiter = SlidingWindowLimiter(RATE_LIMIT_PER_MINUTE)


def get_or_create_host_key() -> asyncssh.SSHKey:
    if HOST_KEY_PATH.exists():
        return asyncssh.read_private_key(str(HOST_KEY_PATH))
    key = asyncssh.generate_private_key("ssh-ed25519")
    HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key(str(HOST_KEY_PATH))
    return key


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, bus: Broadcaster) -> None:
        self._bus = bus
        self._conn: asyncssh.SSHServerConnection | None = None
        self._source_ip = "0.0.0.0"

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        self._source_ip = peer[0] if peer else "0.0.0.0"

        if not _limiter.allow(self._source_ip):
            if _limiter.should_report(self._source_ip):
                logger.warning(
                    "rate limit exceeded for %s (%d/min) -- dropping connections",
                    self._source_ip,
                    RATE_LIMIT_PER_MINUTE,
                )
            conn.abort()

    def begin_auth(self, username: str) -> bool:
        return True  # False here would mean "no auth required at all"

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        success = password == SSH_PASSWORD
        self._bus.publish_soon(
            Event(
                sensor_id=SENSOR_ID,
                service="ssh",
                event_type="auth_attempt",
                source_ip=self._source_ip,
                payload={
                    "username": username,
                    "password": password,
                    "success": success,
                },
            )
        )
        return success


def make_server_factory(bus: Broadcaster):
    return lambda: HoneypotSSHServer(bus)


def make_process_factory(bus: Broadcaster):
    async def handle_client(process: asyncssh.SSHServerProcess) -> None:
        username = process.get_extra_info("username") or "root"
        peer = process.get_extra_info("peername")
        source_ip = peer[0] if peer else "0.0.0.0"
        cwd = "/root"
        session_id = str(uuid.uuid4())

        term_size = process.get_terminal_size()
        recorder = SessionRecorder(
            width=term_size[0] or 80, height=term_size[1] or 24
        )

        def emit(text: str) -> None:
            """Write to the client and to the recording."""
            process.stdout.write(text)
            recorder.write(text)

        await bus.publish(
            Event(
                sensor_id=SENSOR_ID,
                service="ssh",
                event_type="session_start",
                source_ip=source_ip,
                session_id=session_id,
                payload={"username": username},
            )
        )

        emit("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n")
        try:
            while True:
                emit(f"{username}@{HOSTNAME}:{cwd}$ ")
                line = await process.stdin.readline()
                if not line:
                    break
                line = line.rstrip("\n")
                # asyncssh echoes typing itself, so add the command to the
                # recording by hand
                recorder.write(line + "\n")
                if not line.strip():
                    continue

                await bus.publish(
                    Event(
                        sensor_id=SENSOR_ID,
                        service="ssh",
                        event_type="command",
                        source_ip=source_ip,
                        session_id=session_id,
                        payload={"command": line},
                    )
                )

                output, cwd, should_exit = run_command(line, cwd, username)
                if output:
                    emit(output)
                if should_exit:
                    break
        except asyncssh.misc.TerminalSizeChanged:
            pass
        except (asyncssh.misc.ConnectionLost, BrokenPipeError):
            pass
        finally:
            await bus.publish(
                Event(
                    sensor_id=SENSOR_ID,
                    service="ssh",
                    event_type="session_end",
                    source_ip=source_ip,
                    session_id=session_id,
                    payload={
                        "username": username,
                        # the pipeline moves this onto the session row
                        "recording": recorder.dump(),
                        "recording_frames": recorder.frame_count,
                    },
                )
            )
            process.exit(0)

    return handle_client


async def start_ssh_server(bus: Broadcaster) -> asyncssh.SSHAcceptor:
    key = get_or_create_host_key()
    listener = await asyncssh.create_server(
        make_server_factory(bus),
        host="0.0.0.0",
        port=SSH_PORT,
        server_host_keys=[key],
        process_factory=make_process_factory(bus),
    )
    logger.info("ssh honeypot listening on :%d (password: %s)", SSH_PORT, SSH_PASSWORD)
    return listener

"""Fake SSH server. Accepts any login and gives a fake shell. Logins and
commands are published to the event bus.
"""

import logging
import os
import uuid
from pathlib import Path

import asyncssh

from app.bus import Broadcaster
from app.fakeshell import HOSTNAME, run_command
from app.schemas import Event

logger = logging.getLogger("hive.sshd")

SENSOR_ID = os.environ.get("SENSOR_ID", "hive-dev")
SSH_PORT = int(os.environ.get("SSH_PORT", "2222"))
HOST_KEY_PATH = Path(os.environ.get("SSH_HOST_KEY_PATH", "/data/ssh_host_key"))


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

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        event = Event(
            sensor_id=SENSOR_ID,
            service="ssh",
            event_type="auth_attempt",
            source_ip=self._source_ip,
            payload={"username": username, "password": password},
        )
        self._bus.publish_soon(event)
        return True  # accept any password


def make_server_factory(bus: Broadcaster):
    return lambda: HoneypotSSHServer(bus)


def make_process_factory(bus: Broadcaster):
    async def handle_client(process: asyncssh.SSHServerProcess) -> None:
        username = process.get_extra_info("username") or "root"
        peer = process.get_extra_info("peername")
        source_ip = peer[0] if peer else "0.0.0.0"
        cwd = "/root"
        session_id = str(uuid.uuid4())

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

        process.stdout.write(
            f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
        )
        try:
            while True:
                process.stdout.write(f"{username}@{HOSTNAME}:{cwd}$ ")
                line = await process.stdin.readline()
                if not line:
                    break
                line = line.rstrip("\n")
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
                    process.stdout.write(output)
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
                    payload={"username": username},
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
    logger.info("ssh honeypot listening on :%d", SSH_PORT)
    return listener

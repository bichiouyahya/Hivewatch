"""Fake HTTP server.

Written on top of raw asyncio sockets instead of FastAPI so malformed
requests from scanners get logged instead of rejected.
"""

import asyncio
import logging
import os

from app.bus import Broadcaster
from app.http_routes import SERVER_HEADER, build_response
from app.schemas import Event

logger = logging.getLogger("hive.httpd")

SENSOR_ID = os.environ.get("SENSOR_ID", "hive-dev")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

READ_TIMEOUT_SECONDS = 5
MAX_HEADER_LINES = 100
MAX_BODY_BYTES = 64 * 1024
MAX_LOGGED_BODY_CHARS = 4096


def parse_request_line(raw: bytes) -> tuple[str, str, str]:
    """Tolerant parser, never raises on garbage input."""
    text = raw.decode("utf-8", errors="replace").strip()
    parts = text.split(" ")
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return text, "", ""


def parse_header_line(raw: bytes) -> tuple[str, str] | None:
    text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
    if ":" not in text:
        return None
    key, _, value = text.partition(":")
    return key.strip().lower(), value.strip()


def build_raw_response(status: int, content_type: str, body: str) -> bytes:
    reason = {200: "OK", 404: "Not Found"}.get(status, "OK")
    body_bytes = body.encode("utf-8")
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Server: {SERVER_HEADER}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return headers.encode("utf-8") + body_bytes


def make_handler(bus: Broadcaster):
    async def handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "0.0.0.0"

        try:
            try:
                raw_request_line = await asyncio.wait_for(
                    reader.readline(), timeout=READ_TIMEOUT_SECONDS
                )
            except (TimeoutError, ConnectionError):
                return

            if not raw_request_line:
                return

            method, path, http_version = parse_request_line(raw_request_line)

            headers: dict[str, str] = {}
            for _ in range(MAX_HEADER_LINES):
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=READ_TIMEOUT_SECONDS
                    )
                except (TimeoutError, ConnectionError):
                    break
                if line in (b"\r\n", b"\n", b""):
                    break
                parsed = parse_header_line(line)
                if parsed:
                    headers[parsed[0]] = parsed[1]

            body = b""
            content_length = headers.get("content-length", "")
            if content_length.isdigit():
                to_read = min(int(content_length), MAX_BODY_BYTES)
                try:
                    body = await asyncio.wait_for(
                        reader.readexactly(to_read), timeout=READ_TIMEOUT_SECONDS
                    )
                except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                    pass

            await bus.publish(
                Event(
                    sensor_id=SENSOR_ID,
                    service="http",
                    event_type="http_request",
                    source_ip=source_ip,
                    payload={
                        "method": method,
                        "path": path,
                        "http_version": http_version,
                        "headers": headers,
                        "body": body.decode("utf-8", errors="replace")[
                            :MAX_LOGGED_BODY_CHARS
                        ],
                    },
                )
            )

            status, content_type, response_body = build_response(path)
            writer.write(build_raw_response(status, content_type, response_body))
            await writer.drain()
        except Exception:
            logger.exception("error handling http connection from %s", source_ip)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    return handle_client


async def start_http_server(bus: Broadcaster) -> asyncio.Server:
    server = await asyncio.start_server(make_handler(bus), host="0.0.0.0", port=HTTP_PORT)
    logger.info("http honeypot listening on :%d", HTTP_PORT)
    return server

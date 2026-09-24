"""Extract indicators of compromise (IPs, URLs, domains, user agents,
credentials) from captured events.
"""

import re
from dataclasses import dataclass
from ipaddress import ip_address

from app.schemas import Event

URL_RE = re.compile(r"https?://[^\s'\"|;>)]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# starting confidence per type, before repeat sightings
BASE_CONFIDENCE = {
    "url": 85,
    "domain": 75,
    "ip": 55,
    "user_agent": 40,
    "credential": 45,
}


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str
    source_service: str

    @property
    def base_confidence(self) -> int:
        return BASE_CONFIDENCE.get(self.type, 50)


def _host_from_url(url: str) -> str | None:
    host = url.split("://", 1)[1].split("/", 1)[0].split("@")[-1]
    host = host.split(":", 1)[0]
    return host or None


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def extract(event: Event) -> list[Indicator]:
    """Indicators found in a single event."""
    found: list[Indicator] = []
    service = event.service
    payload = event.payload

    # the source address itself
    found.append(Indicator("ip", str(event.source_ip), service))

    if event.event_type == "command":
        command = str(payload.get("command", ""))
        for url in URL_RE.findall(command):
            url = url.rstrip(".,;")
            found.append(Indicator("url", url, service))
            host = _host_from_url(url)
            if host:
                found.append(
                    Indicator("ip" if _is_ip(host) else "domain", host, service)
                )
        # plain IPs in a command (scp/nc targets)
        for raw_ip in IPV4_RE.findall(command):
            if _is_ip(raw_ip):
                found.append(Indicator("ip", raw_ip, service))

    elif event.event_type == "http_request":
        headers = payload.get("headers") or {}
        agent = headers.get("user-agent") if isinstance(headers, dict) else None
        if agent:
            found.append(Indicator("user_agent", str(agent)[:512], service))

    elif event.event_type == "auth_attempt":
        username = payload.get("username")
        password = payload.get("password")
        if username is not None and password is not None:
            found.append(Indicator("credential", f"{username}:{password}", service))

    # drop duplicates (a URL host can also match the bare-IP pass)
    return list(dict.fromkeys(found))

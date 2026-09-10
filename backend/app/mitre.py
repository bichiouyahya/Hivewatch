"""MITRE ATT&CK technique detection.

- Pattern rules: a single command or HTTP path maps to a technique.
- Sliding window rules: per-IP state over time (e.g. brute force).
  State is kept in memory only.
"""

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

TECHNIQUE_NAMES: dict[str, str] = {
    "T1082": "Discovery: System Information Discovery",
    "T1033": "Discovery: System Owner/User Discovery",
    "T1083": "Discovery: File and Directory Discovery",
    "T1552.001": "Credential Access: Credentials In Files",
    "T1105": "Command and Control: Ingress Tool Transfer",
    "T1053.003": "Persistence: Scheduled Task/Job - Cron",
    "T1110": "Credential Access: Brute Force",
    "T1046": "Discovery: Network Service Scanning",
    "T1595.002": "Reconnaissance: Active Scanning - Vulnerability Scanning",
}

COMMAND_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^cat\s+.*(passwd|shadow|\.ssh/|\.env|id_rsa)", re.IGNORECASE), "T1552.001"),
    (re.compile(r"^(uname|hostname)\b", re.IGNORECASE), "T1082"),
    (re.compile(r"^(whoami|id)\b", re.IGNORECASE), "T1033"),
    (re.compile(r"^(ls|pwd|find)\b", re.IGNORECASE), "T1083"),
    (re.compile(r"^(wget|curl)\b", re.IGNORECASE), "T1105"),
    (re.compile(r"^crontab\b", re.IGNORECASE), "T1053.003"),
]

# requests to these paths = vulnerability scanning
SCANNED_PATH_PREFIXES = (
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/xmlrpc.php",
    "/.env",
    "/.git",
)

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

# low for now since there are only 2 services
SERVICE_DISCOVERY_THRESHOLD = 2
SERVICE_DISCOVERY_WINDOW = timedelta(seconds=60)


def match_command(command: str) -> set[str]:
    return {technique for pattern, technique in COMMAND_RULES if pattern.search(command)}


def match_http_path(path: str) -> set[str]:
    clean_path = path.split("?", 1)[0].lower()
    if any(clean_path.startswith(prefix) for prefix in SCANNED_PATH_PREFIXES):
        return {"T1595.002"}
    return set()


class SlidingWindowDetector:
    """Tracks per-IP activity over time."""

    def __init__(self) -> None:
        self._auth_attempts: dict[str, deque[datetime]] = defaultdict(deque)
        self._service_touches: dict[str, dict[str, datetime]] = defaultdict(dict)

    def record_auth_attempt(self, ip: str, when: datetime) -> bool:
        """True if the IP hit the brute-force threshold in the window."""
        window = self._auth_attempts[ip]
        window.append(when)
        cutoff = when - BRUTE_FORCE_WINDOW
        while window and window[0] < cutoff:
            window.popleft()
        return len(window) >= BRUTE_FORCE_THRESHOLD

    def record_service_touch(self, ip: str, service: str, when: datetime) -> bool:
        """True if the IP touched multiple services in the window."""
        touches = self._service_touches[ip]
        touches[service] = when
        cutoff = when - SERVICE_DISCOVERY_WINDOW
        recent_services = {svc for svc, seen_at in touches.items() if seen_at >= cutoff}
        return len(recent_services) >= SERVICE_DISCOVERY_THRESHOLD

"""MITRE ATT&CK technique detection.

- Pattern rules: a single command or HTTP path maps to a technique.
- Sliding window rules: per-IP state over time (e.g. brute force).
  State is kept in memory only.
"""

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# tactics in kill-chain order, used for the heatmap columns
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Credential Access",
    "Discovery",
    "Command and Control",
    "Impact",
)

# every technique the rules can produce: id -> (name, tactic)
TECHNIQUE_CATALOG: dict[str, tuple[str, str]] = {
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1046": ("Network Service Scanning", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
}

# "Tactic: Name" labels for alerts and logs
TECHNIQUE_NAMES: dict[str, str] = {
    tid: f"{tactic}: {name}" for tid, (name, tactic) in TECHNIQUE_CATALOG.items()
}

# these count as a breach attempt rather than recon
CRITICAL_TECHNIQUES = frozenset({"T1110", "T1552.001"})


def severity_for(techniques: list[str] | None) -> str:
    """Severity label shared by the API and the dashboard."""
    if not techniques:
        return "LOW"
    if CRITICAL_TECHNIQUES.intersection(techniques):
        return "CRITICAL"
    return "HIGH"


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

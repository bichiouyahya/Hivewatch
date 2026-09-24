"""Export stored IOCs as a STIX 2.1 bundle or as firewall/web server
blocklists.
"""

import csv
import io
from typing import Any

from stix2 import Bundle, Indicator

# credentials are left out: there's no STIX pattern for a guessed
# username/password pair
PATTERN_BUILDERS = {
    "ip": lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "user_agent": (
        lambda v: "[network-traffic:extensions.'http-request-ext'"
        f".request_header.'User-Agent' = '{v}']"
    ),
}

BLOCKLIST_FORMATS = ("plain", "iptables", "nginx", "csv")


def _escape(value: str) -> str:
    """Escape quotes and backslashes so the STIX pattern stays valid."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_stix_bundle(rows: list[dict[str, Any]]) -> dict[str, Any]:
    indicators = []
    for row in rows:
        builder = PATTERN_BUILDERS.get(row["ioc_type"])
        if builder is None:
            continue
        indicators.append(
            Indicator(
                name=f"{row['ioc_type']}: {row['value']}",
                description=(
                    f"Observed by the Hive honeypot on the {row['source_service']} "
                    f"service {row['hit_count']} time(s)."
                ),
                pattern=builder(_escape(row["value"])),
                pattern_type="stix",
                valid_from=row["first_seen"],
                created=row["first_seen"],
                modified=row["last_seen"],
                confidence=row["confidence"],
                labels=["malicious-activity"],
            )
        )

    if not indicators:
        # a Bundle needs at least one object, so build the empty one by hand
        return {"type": "bundle", "id": Bundle().id, "objects": []}

    return Bundle(*indicators, allow_custom=False).serialize(pretty=False, ensure_ascii=False)


def build_blocklist(rows: list[dict[str, Any]], fmt: str) -> str:
    """Build a blocklist. Only IP indicators are usable here."""
    ips = [row for row in rows if row["ioc_type"] == "ip"]

    if fmt == "iptables":
        lines = [f"iptables -A INPUT -s {r['value']} -j DROP" for r in ips]
    elif fmt == "nginx":
        lines = [f"deny {r['value']};" for r in ips]
    elif fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["ip", "hit_count", "confidence", "first_seen", "last_seen"])
        for r in ips:
            writer.writerow(
                [
                    r["value"],
                    r["hit_count"],
                    r["confidence"],
                    r["first_seen"].isoformat(),
                    r["last_seen"].isoformat(),
                ]
            )
        return buffer.getvalue()
    else:  # plain
        lines = [r["value"] for r in ips]

    header = [
        "# Hive honeypot blocklist",
        f"# {len(ips)} address(es)",
    ]
    return "\n".join(header + lines) + "\n"

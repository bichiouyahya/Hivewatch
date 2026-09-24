import json
from datetime import datetime, timezone

from app.intel import build_blocklist, build_stix_bundle


def row(ioc_type: str, value: str, **overrides) -> dict:
    base = dict(
        ioc_type=ioc_type,
        value=value,
        source_service="ssh",
        hit_count=3,
        confidence=80,
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    return {**base, **overrides}


def bundle_of(rows) -> dict:
    raw = build_stix_bundle(rows)
    return json.loads(raw) if isinstance(raw, str) else raw


def test_bundle_is_a_stix_bundle_with_one_indicator_per_ioc():
    b = bundle_of([row("ip", "203.0.113.7"), row("domain", "evil.example.com")])
    assert b["type"] == "bundle"
    assert [o["type"] for o in b["objects"]] == ["indicator", "indicator"]


def test_patterns_use_the_right_stix_observable_per_type():
    b = bundle_of(
        [
            row("ip", "203.0.113.7"),
            row("domain", "evil.example.com"),
            row("url", "http://evil.example.com/a.sh"),
        ]
    )
    patterns = {o["pattern"] for o in b["objects"]}
    assert "[ipv4-addr:value = '203.0.113.7']" in patterns
    assert "[domain-name:value = 'evil.example.com']" in patterns
    assert "[url:value = 'http://evil.example.com/a.sh']" in patterns


def test_credentials_are_excluded_from_stix():
    # credentials have no STIX pattern
    b = bundle_of([row("credential", "root:adminpass"), row("ip", "203.0.113.7")])
    assert len(b["objects"]) == 1


def test_quotes_in_a_value_are_escaped_so_the_pattern_stays_valid():
    b = bundle_of([row("user_agent", "evil'; DROP TABLE--")])
    assert "\\'" in b["objects"][0]["pattern"]


def test_empty_ioc_set_still_produces_a_valid_bundle():
    b = bundle_of([])
    assert b["type"] == "bundle"
    assert b["objects"] == []


def test_blocklist_plain_lists_only_ips():
    out = build_blocklist(
        [row("ip", "203.0.113.7"), row("domain", "evil.example.com")], "plain"
    )
    assert "203.0.113.7" in out
    assert "evil.example.com" not in out


def test_blocklist_iptables_format():
    out = build_blocklist([row("ip", "203.0.113.7")], "iptables")
    assert "iptables -A INPUT -s 203.0.113.7 -j DROP" in out


def test_blocklist_nginx_format():
    out = build_blocklist([row("ip", "203.0.113.7")], "nginx")
    assert "deny 203.0.113.7;" in out


def test_blocklist_csv_has_a_header_and_no_comment_lines():
    out = build_blocklist([row("ip", "203.0.113.7")], "csv")
    assert out.splitlines()[0] == "ip,hit_count,confidence,first_seen,last_seen"
    assert not out.startswith("#")

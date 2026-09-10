from datetime import datetime, timedelta, timezone

from app.mitre import SlidingWindowDetector, match_command, match_http_path


def test_match_command_detects_credential_access():
    assert "T1552.001" in match_command("cat /etc/passwd")


def test_match_command_no_match_for_unknown_command():
    assert match_command("thiscommanddoesnotexist") == set()


def test_match_command_can_return_multiple_techniques():
    techniques = match_command("cat ~/.ssh/id_rsa")
    assert "T1552.001" in techniques


def test_match_http_path_detects_scanned_bait_path():
    assert match_http_path("/wp-login.php") == {"T1595.002"}


def test_match_http_path_ignores_query_string():
    assert match_http_path("/wp-login.php?redirect_to=/wp-admin/") == {"T1595.002"}


def test_match_http_path_no_match_for_normal_path():
    assert match_http_path("/") == set()


def _t(seconds_offset: int) -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds_offset)


def test_brute_force_does_not_trigger_below_threshold():
    detector = SlidingWindowDetector()
    for i in range(4):
        triggered = detector.record_auth_attempt("203.0.113.7", _t(i))
    assert triggered is False


def test_brute_force_triggers_at_threshold_within_window():
    detector = SlidingWindowDetector()
    triggered = False
    for i in range(5):
        triggered = detector.record_auth_attempt("203.0.113.7", _t(i))
    assert triggered is True


def test_brute_force_does_not_count_attempts_outside_window():
    detector = SlidingWindowDetector()
    # 3 attempts, 6 min gap, 2 more
    for i in range(3):
        detector.record_auth_attempt("203.0.113.7", _t(i))
    triggered = False
    for i in range(2):
        triggered = detector.record_auth_attempt("203.0.113.7", _t(400 + i))
    assert triggered is False


def test_brute_force_tracks_each_ip_independently():
    detector = SlidingWindowDetector()
    for i in range(4):
        detector.record_auth_attempt("203.0.113.7", _t(i))
    triggered = detector.record_auth_attempt("198.51.100.9", _t(4))
    assert triggered is False


def test_service_discovery_does_not_trigger_for_single_service():
    detector = SlidingWindowDetector()
    detector.record_service_touch("203.0.113.7", "ssh", _t(0))
    triggered = detector.record_service_touch("203.0.113.7", "ssh", _t(1))
    assert triggered is False


def test_service_discovery_triggers_across_distinct_services():
    detector = SlidingWindowDetector()
    detector.record_service_touch("203.0.113.7", "ssh", _t(0))
    triggered = detector.record_service_touch("203.0.113.7", "http", _t(5))
    assert triggered is True


def test_service_discovery_does_not_count_stale_touches():
    detector = SlidingWindowDetector()
    detector.record_service_touch("203.0.113.7", "ssh", _t(0))
    triggered = detector.record_service_touch("203.0.113.7", "http", _t(120))
    assert triggered is False

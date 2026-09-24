import time

from app.ratelimit import SlidingWindowLimiter


def test_allows_up_to_the_limit():
    limiter = SlidingWindowLimiter(limit=3)
    assert [limiter.allow("1.2.3.4") for _ in range(3)] == [True, True, True]


def test_blocks_once_over_the_limit():
    limiter = SlidingWindowLimiter(limit=3)
    for _ in range(3):
        limiter.allow("1.2.3.4")
    assert limiter.allow("1.2.3.4") is False


def test_each_source_has_its_own_budget():
    limiter = SlidingWindowLimiter(limit=2)
    limiter.allow("1.2.3.4")
    limiter.allow("1.2.3.4")
    assert limiter.allow("1.2.3.4") is False
    assert limiter.allow("5.6.7.8") is True


def test_window_expires_so_a_source_recovers():
    limiter = SlidingWindowLimiter(limit=2, window_seconds=0)
    limiter.allow("1.2.3.4")
    limiter.allow("1.2.3.4")
    time.sleep(0.01)
    assert limiter.allow("1.2.3.4") is True


def test_blocked_attempts_do_not_extend_the_window():
    # only accepted attempts are recorded
    limiter = SlidingWindowLimiter(limit=1)
    assert limiter.allow("1.2.3.4") is True
    for _ in range(50):
        limiter.allow("1.2.3.4")
    assert len(limiter._hits["1.2.3.4"]) == 1


def test_reporting_is_throttled_per_source():
    limiter = SlidingWindowLimiter(limit=1)
    assert limiter.should_report("1.2.3.4") is True
    assert limiter.should_report("1.2.3.4") is False
    assert limiter.should_report("5.6.7.8") is True


def test_expired_sources_are_swept_so_the_table_stays_bounded():
    limiter = SlidingWindowLimiter(limit=5, window_seconds=0)
    for i in range(50):
        limiter.allow(f"10.0.0.{i}")
    time.sleep(0.01)
    limiter._sweep(time.monotonic())
    assert limiter.tracked_sources == 0

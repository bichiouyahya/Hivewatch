"""Per-source rate limiting for the honeypot listeners.

This isn't meant to keep attackers out, it's to stop one flood from
filling the disk and starving the pipeline, since every connection
means database writes. The default limit is high for that reason.
"""

import time
from collections import defaultdict, deque

# clear out stale keys once the table gets this big
SWEEP_THRESHOLD = 4096


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_report: dict[str, float] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        window = self._hits[key]
        cutoff = now - self.window
        while window and window[0] < cutoff:
            window.popleft()
        return window

    def _sweep(self, now: float) -> None:
        cutoff = now - self.window
        for key in [k for k, v in self._hits.items() if not v or v[-1] < cutoff]:
            self._hits.pop(key, None)
            self._last_report.pop(key, None)

    def allow(self, key: str) -> bool:
        """Records an attempt and returns whether it's within the limit."""
        now = time.monotonic()
        if len(self._hits) > SWEEP_THRESHOLD:
            self._sweep(now)

        window = self._prune(key, now)
        if len(window) >= self.limit:
            return False
        window.append(now)
        return True

    def should_report(self, key: str, every_seconds: int = 60) -> bool:
        """Limits how often a blocked source is logged."""
        now = time.monotonic()
        last = self._last_report.get(key)
        if last is not None and now - last < every_seconds:
            return False
        self._last_report[key] = now
        return True

    @property
    def tracked_sources(self) -> int:
        return len(self._hits)

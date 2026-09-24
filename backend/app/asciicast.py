"""Records a fake-shell session in asciicast v2 format (what asciinema
produces), so recordings play in any compatible player.

Format is a JSON header line, then one JSON array per frame:
[seconds_since_start, "o", text].
"""

import json
import time

MAX_FRAMES = 2000
MAX_TOTAL_CHARS = 256 * 1024


class SessionRecorder:
    def __init__(self, width: int = 80, height: int = 24) -> None:
        self._start = time.monotonic()
        self._width = width
        self._height = height
        self._frames: list[tuple[float, str]] = []
        self._chars = 0
        self.truncated = False

    def write(self, text: str) -> None:
        """Record terminal output. Stops once the size caps are hit; the
        session keeps working, only the recording is cut short.
        """
        if not text or self.truncated:
            return
        if len(self._frames) >= MAX_FRAMES or self._chars + len(text) > MAX_TOTAL_CHARS:
            self.truncated = True
            self._frames.append(
                (time.monotonic() - self._start, "\r\n[recording truncated]\r\n")
            )
            return
        self._frames.append((time.monotonic() - self._start, text))
        self._chars += len(text)

    @property
    def frame_count(self) -> int:
        return len(self._frames)

    def dump(self) -> str:
        header = {
            "version": 2,
            "width": self._width,
            "height": self._height,
            "timestamp": int(time.time()),
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        }
        lines = [json.dumps(header)]
        for offset, text in self._frames:
            lines.append(json.dumps([round(offset, 6), "o", text]))
        return "\n".join(lines) + "\n"

"""Bounded in-memory sliding-window limiter for the first prototype."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int, *, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._entries: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if key not in self._entries and len(self._entries) >= self.max_keys:
                oldest = min(
                    self._entries,
                    key=lambda entry: self._entries[entry][-1] if self._entries[entry] else 0,
                )
                self._entries.pop(oldest, None)
            queue = self._entries[key]
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(now)
            return True

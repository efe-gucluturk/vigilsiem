"""In-memory sliding-window rate limiter with bounded memory (LRU key eviction)."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: int  # whole seconds; 0 when allowed
    remaining: int


class SlidingWindowLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        *,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("invalid limiter configuration")
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, key: str) -> RateDecision:
        """Record a hit for ``key`` if allowed. Denied attempts are not recorded."""
        now = self._clock()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                hits = deque()
                self._hits[key] = hits
            while hits and hits[0] <= cutoff:
                hits.popleft()
            self._hits.move_to_end(key)
            if len(hits) >= self.limit:
                retry = max(1, math.ceil(hits[0] + self.window - now))
                return RateDecision(False, retry, 0)
            hits.append(now)
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
            return RateDecision(True, 0, self.limit - len(hits))

    def is_limited(self, key: str) -> bool:
        """Non-recording peek: has ``key`` already used up its window?"""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return False
            return sum(1 for t in hits if t > now - self.window) >= self.limit

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

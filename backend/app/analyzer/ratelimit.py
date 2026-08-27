"""Client-side rate limiting.

The Gemini free tier is 15 requests/minute on the -lite models (5 on the full
flash models). A mail inbox rendering 30 messages will blow through that in
one page load, and the server's answer is a 429 with a ~50 second retry
delay -- which, in a browser extension, is indistinguishable from "broken".

So we pace ourselves instead of finding out the hard way. A request that
waits 4s locally is strictly better than one that gets rejected and waits 50s.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    """Sliding-window limiter. Async-safe, fair (FIFO via the lock)."""

    def __init__(self, per_minute: int = 15, window: float = 60.0):
        self.per_minute = per_minute
        self.window = window
        self._hits: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """Block until a slot is free. Returns seconds waited (for logging)."""
        waited = 0.0
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._hits and now - self._hits[0] >= self.window:
                    self._hits.popleft()

                if len(self._hits) < self.per_minute:
                    self._hits.append(now)
                    return waited

                # Sleep until the oldest hit falls out of the window.
                sleep_for = self.window - (now - self._hits[0]) + 0.05

            await asyncio.sleep(sleep_for)
            waited += sleep_for

    def snapshot(self) -> tuple[int, int]:
        """(used, capacity) in the current window -- for /health."""
        now = time.monotonic()
        used = sum(1 for h in self._hits if now - h < self.window)
        return used, self.per_minute

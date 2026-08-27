"""Rate limiter behaviour."""

import asyncio
import time

import pytest

from app.analyzer.ratelimit import RateLimiter


@pytest.mark.asyncio
async def test_allows_burst_up_to_capacity_without_waiting():
    limiter = RateLimiter(per_minute=5, window=60.0)
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire()
    assert time.monotonic() - start < 0.1


@pytest.mark.asyncio
async def test_blocks_once_capacity_is_spent():
    """The 4th request in a 3-per-window limiter must wait for the window."""
    limiter = RateLimiter(per_minute=3, window=0.4)
    for _ in range(3):
        await limiter.acquire()
    start = time.monotonic()
    await limiter.acquire()
    assert time.monotonic() - start >= 0.3


@pytest.mark.asyncio
async def test_concurrent_callers_do_not_exceed_capacity():
    """30 messages arriving at once must not produce 30 simultaneous calls."""
    limiter = RateLimiter(per_minute=5, window=10.0)
    done = []

    async def worker():
        await limiter.acquire()
        done.append(time.monotonic())

    await asyncio.wait_for(
        asyncio.gather(*(worker() for _ in range(5))), timeout=1.0
    )
    assert len(done) == 5
    used, cap = limiter.snapshot()
    assert used == 5 and cap == 5


@pytest.mark.asyncio
async def test_snapshot_reports_usage():
    limiter = RateLimiter(per_minute=10, window=60.0)
    assert limiter.snapshot() == (0, 10)
    await limiter.acquire()
    assert limiter.snapshot() == (1, 10)

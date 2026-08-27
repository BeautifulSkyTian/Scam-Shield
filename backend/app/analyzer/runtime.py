"""Bridge between the async analyzer and FastAPI's synchronous endpoints.

`main.py` defines its routes with `def`, not `async def`, because the SQLAlchemy
session is synchronous -- making those routes async would block the event loop
on every database call. That decision is correct, so the analyzer adapts to it
rather than the other way round.

The naive bridge is `asyncio.run(...)` per request. Don't: it builds and tears
down an event loop every call, which discards the HTTP connection pool AND the
rate limiter's state. Losing the rate limiter is the serious one -- it is the
only thing keeping us inside the free tier's 15 requests/minute.

So: one event loop, on one daemon thread, for the process lifetime. Requests
are submitted to it from FastAPI's threadpool workers. The analyzer is built
inside that loop, so its lock and client are bound to the loop that uses them.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Coroutine

from .engine import ScamAnalyzer


class AnalyzerRuntime:
    """Owns the analyzer and the loop it runs on. Create one, share it."""

    def __init__(self, default_timeout: float = 30.0, **analyzer_kwargs: Any):
        self.default_timeout = default_timeout
        self._analyzer_kwargs = analyzer_kwargs
        self._analyzer: ScamAnalyzer | None = None
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._run_loop, name="analyzer-loop", daemon=True
        )
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.call_soon(self._ready.set)
        self._loop.run_forever()

    @property
    def analyzer(self) -> ScamAnalyzer:
        """Built lazily, on first use, from inside the loop thread."""
        if self._analyzer is None:
            self._analyzer = self.submit(self._build(), timeout=15.0)
        return self._analyzer

    async def _build(self) -> ScamAnalyzer:
        return ScamAnalyzer(**self._analyzer_kwargs)

    def submit(self, coro: Coroutine, timeout: float | None = None) -> Any:
        """Run a coroutine on the analyzer loop and wait for the result.

        Raises TimeoutError if it overruns -- the caller turns that into a 504
        rather than letting a content script hang forever.
        """
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout or self.default_timeout)
        except TimeoutError:
            future.cancel()
            raise

    def shutdown(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=2.0)

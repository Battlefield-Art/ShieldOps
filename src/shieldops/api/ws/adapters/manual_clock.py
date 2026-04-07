"""Manual clock — deterministic time for contract tests.

Satisfies :class:`shieldops.api.ws.core.ports.Clock`. Lets the Hub's
heartbeat loop be tested without ``asyncio.sleep(20)`` burning real
seconds.
"""

from __future__ import annotations

from datetime import UTC, datetime


class ManualClock:
    """Controllable clock. Use :meth:`advance` to move time forward.

    ``sleep`` is a no-op that advances the internal time — so code
    that calls ``await clock.sleep(N)`` runs synchronously in tests
    but still observes the new time on the next ``now()``.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)

    def now(self) -> datetime:
        return datetime.fromtimestamp(self._now, tz=UTC)

    def advance(self, seconds: float) -> None:
        self._now += float(seconds)

    async def sleep(self, seconds: float) -> None:
        # Deterministic: advancing time instead of actually sleeping.
        self._now += float(seconds)

    # Convenience for tests that want a monotonic float instead of datetime.
    def timestamp(self) -> float:
        return self._now

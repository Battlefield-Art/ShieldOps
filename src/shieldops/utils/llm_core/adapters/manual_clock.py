"""Manual clock for the LLM orchestrator contract tests.

Distinct from the WebSocket/policy ManualClocks because the LLM
``Clock`` port needs ``async def sleep`` (so retry timing is
deterministic). Keeping the adapter local to its port avoids cross-module
dependencies between unrelated RFCs.
"""

from __future__ import annotations


class ManualClock:
    """Controllable clock returning a Unix timestamp.

    ``sleep`` advances the internal clock instead of actually sleeping,
    so retry loops run synchronously in tests but still observe the
    new time on the next ``now()``.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)

    def now(self) -> float:
        return self._now

    async def sleep(self, seconds: float) -> None:
        self._now += float(seconds)

    def advance(self, seconds: float) -> None:
        self._now += float(seconds)

"""Manual clock — returns a Unix timestamp, controlled by ``advance``.

Satisfies :class:`shieldops.api.policy.ports.Clock`. This is the same
shape as the WebSocket Hub's :class:`shieldops.api.ws.adapters.ManualClock`
but returns a float (for bucket math) instead of a datetime. The two
classes are deliberately kept separate so each RFC's port definition
stays minimal.
"""

from __future__ import annotations


class ManualClock:
    """Deterministic clock for rate-limit tests.

    Usage::

        clock = ManualClock(start=0.0)
        # run 5 requests at t=0.0 ...
        clock.advance(1.0)
        # run 1 more at t=1.0 ...
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += float(seconds)

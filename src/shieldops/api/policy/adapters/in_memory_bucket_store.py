"""In-memory token bucket store — deterministic rate-limit state for tests.

Implements :class:`shieldops.api.policy.ports.BucketStore`. Production
uses a Redis Lua script for atomicity across replicas; the in-memory
variant here uses a simple ``threading.Lock`` because tests are
single-threaded and driven by an injected clock.

Algorithm (classic token bucket):

- Per-key state: ``(tokens, last_refill_ts)``.
- On ``take(key, capacity, refill_per_sec, cost, now)``:
    1. ``elapsed = now - last_refill_ts``
    2. ``tokens = min(capacity, tokens + elapsed * refill_per_sec)``
    3. If ``tokens >= cost``: consume, allowed=True, retry_after=0
    4. Else: allowed=False, retry_after = ``(cost - tokens) / refill_per_sec``
    5. Save ``(tokens, now)``.

The bucket starts **full** on first contact (``tokens = capacity``).
This matches the standard token-bucket behavior and means the first
``capacity`` requests in a burst all succeed — which is exactly what
the contract test asserts.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class _BucketState:
    tokens: float
    last_refill_ts: float


class InMemoryBucketStore:
    """In-process token bucket. Safe for single-process contract tests."""

    def __init__(self) -> None:
        self._buckets: dict[str, _BucketState] = {}
        self._lock = threading.Lock()

    async def take(
        self,
        key: str,
        capacity: int,
        refill_per_sec: float,
        cost: int,
        now: float,
    ) -> tuple[bool, float]:
        if capacity <= 0:
            return (False, float("inf"))
        if cost > capacity:
            return (False, float("inf"))

        with self._lock:
            state = self._buckets.get(key)
            if state is None:
                # New bucket — start full.
                state = _BucketState(tokens=float(capacity), last_refill_ts=now)
                self._buckets[key] = state

            # Refill based on elapsed time.
            elapsed = max(0.0, now - state.last_refill_ts)
            state.tokens = min(float(capacity), state.tokens + elapsed * refill_per_sec)
            state.last_refill_ts = now

            if state.tokens >= cost:
                state.tokens -= cost
                return (True, 0.0)

            deficit = cost - state.tokens
            retry_after = deficit / refill_per_sec if refill_per_sec > 0 else float("inf")
            return (False, retry_after)

    # -- Test inspection ---------------------------------------------------

    def current_tokens(self, key: str) -> float | None:
        state = self._buckets.get(key)
        return state.tokens if state is not None else None

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

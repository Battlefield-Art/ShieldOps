"""In-memory ``Buffer`` adapter — per-channel ring buffer.

Satisfies :class:`shieldops.api.ws.core.ports.Buffer`. This is the
default production buffer for single-process deployments — fast, no
external dependencies. Multi-replica deployments can later add a
``RedisStreamsBuffer`` adapter against the same Protocol without any
core changes.

Eviction policy: per-channel FIFO with a max length. If a caller
queries :meth:`since` with a ``since_id`` older than the oldest
retained event (i.e. evicted), the buffer yields the entire current
window so the client can self-recover — the same contract as
``EventBuffer.replay_since`` in the TDD round 3 implementation.
"""

from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator

from shieldops.api.ws.core.events import BufferedEvent


class InMemoryBuffer:
    """In-process ring buffer, keyed by channel."""

    def __init__(self, max_per_channel: int = 1000) -> None:
        if max_per_channel <= 0:
            raise ValueError("max_per_channel must be positive")
        self._max = max_per_channel
        self._events: dict[str, deque[BufferedEvent]] = {}

    async def append(
        self,
        channel: str,
        event_id: str,
        payload: bytes,
        ts: float,
    ) -> None:
        if channel not in self._events:
            self._events[channel] = deque(maxlen=self._max)
        self._events[channel].append(
            BufferedEvent(
                id=event_id,
                kind="",
                payload=payload,
                ts=ts,
                channel=channel,
            )
        )

    async def since(
        self,
        channel: str,
        since_id: str | None,
    ) -> AsyncIterator[BufferedEvent]:
        """Yield events strictly newer than ``since_id``.

        - ``since_id=None`` → yield the entire current window.
        - ``since_id`` not found in the buffer (evicted or unknown) →
          yield the entire current window (self-recovery).
        - ``since_id`` found → yield events after that id (exclusive).
        """
        window = list(self._events.get(channel, ()))
        if not window:
            return

        if since_id is None:
            for evt in window:
                yield evt
            return

        # Find the since_id in the window. If present, yield everything
        # after it. If absent, yield the full window.
        found_index: int | None = None
        for i, evt in enumerate(window):
            if evt.id == since_id:
                found_index = i
                break

        if found_index is None:
            # since_id evicted or unknown — yield full window so client
            # reconnects cleanly.
            for evt in window:
                yield evt
            return

        for evt in window[found_index + 1 :]:
            yield evt

    async def trim(
        self,
        channel: str,
        max_age_s: float,
        max_len: int,
    ) -> None:
        """Best-effort trim. The deque already enforces ``max_len`` via
        ``maxlen``, so this method only enforces ``max_age_s``.
        """
        q = self._events.get(channel)
        if q is None:
            return
        # Drop any events older than max_age_s
        # (ts is a Unix timestamp; comparison is against the newest event's ts).
        if not q:
            return
        newest_ts = q[-1].ts
        cutoff = newest_ts - max_age_s
        while q and q[0].ts < cutoff:
            q.popleft()

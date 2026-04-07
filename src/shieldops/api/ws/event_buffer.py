"""Per-org WebSocket event buffer with replay support (#5 Round 3).

When a dashboard WebSocket disconnects briefly (network blip, page reload),
the client can reconnect with the last event ID it received and call
:meth:`EventBuffer.replay_since` to recover any messages it missed.

The buffer is bounded per org via a deque so memory cannot grow without bound.
Events older than ``max_per_org`` are silently evicted; clients that ask for
an evicted ID still receive the full current window so they self-recover
rather than fail.

This module is intentionally synchronous and dependency-free — it slots in
front of the existing async broadcaster without contention.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from itertools import count
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class EventBuffer:
    """Bounded per-org ring buffer for replay-on-reconnect."""

    def __init__(self, *, max_per_org: int = 1000) -> None:
        if max_per_org <= 0:
            raise ValueError("max_per_org must be positive")
        self._max = max_per_org
        self._events: dict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self._max)
        )
        self._counter = count(start=1)
        self._lock = threading.Lock()

    def append(self, org_id: str, data: dict[str, Any]) -> int:
        """Record one event for ``org_id``. Returns the assigned event ID."""
        with self._lock:
            event_id = next(self._counter)
            self._events[org_id].append({"id": event_id, "data": data})
            return event_id

    def replay_since(self, org_id: str, *, since_id: int | None) -> list[dict[str, Any]]:
        """Return events for ``org_id`` newer than ``since_id`` (exclusive).

        - ``since_id=None`` returns the entire current window.
        - If ``since_id`` is older than the buffer's earliest event (i.e. it
          has been evicted), the entire current window is returned so the
          caller can self-recover.
        """
        with self._lock:
            window = self._events.get(org_id)
            if not window:
                return []
            if since_id is None:
                return list(window)
            earliest_id = window[0]["id"]
            if since_id < earliest_id:
                return list(window)
            return [evt for evt in window if evt["id"] > since_id]

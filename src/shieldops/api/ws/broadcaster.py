"""Real-time event broadcaster for ShieldOps dashboards.

Holds per-org WebSocket connection registries and fans out events to
subscribers. Designed to be a process-wide singleton accessed via
:func:`get_broadcaster`.

Event envelope shape (sent as JSON over the wire)::

    {
        "type": "new_situation" | "agent_status_change" | "firewall_event" | "metric_update",
        "org_id": "<org>",
        "data": {...},
        "ts": 1712345678.123,
    }
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import defaultdict
from enum import StrEnum
from typing import Any

import structlog
from starlette.websockets import WebSocket, WebSocketState

logger = structlog.get_logger()


# --- Constants ---------------------------------------------------------------

MAX_CONNECTIONS: int = 1000
HEARTBEAT_INTERVAL_S: float = 30.0
HEARTBEAT_TIMEOUT_S: float = 60.0
_ADMIN_CHANNEL: str = "__admin__"


class RealtimeEventType(StrEnum):
    AGENT_STATUS_CHANGE = "agent_status_change"
    NEW_SITUATION = "new_situation"
    FIREWALL_EVENT = "firewall_event"
    METRIC_UPDATE = "metric_update"


# --- Connection wrapper ------------------------------------------------------


class _Connection:
    """Per-WebSocket bookkeeping."""

    __slots__ = ("websocket", "org_id", "last_pong", "connected_at")

    def __init__(self, websocket: WebSocket, org_id: str) -> None:
        self.websocket = websocket
        self.org_id = org_id
        self.last_pong: float = time.time()
        self.connected_at: float = time.time()

    def is_stale(self, now: float | None = None) -> bool:
        now = now or time.time()
        return (now - self.last_pong) > HEARTBEAT_TIMEOUT_S


# --- Broadcaster -------------------------------------------------------------


class Broadcaster:
    """Singleton fan-out hub for per-org WebSocket events."""

    def __init__(self) -> None:
        self._by_org: dict[str, set[_Connection]] = defaultdict(set)
        self._all: set[_Connection] = set()
        self._lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task[None] | None = None

    # -- Registration -----------------------------------------------------

    async def subscribe(self, org_id: str, websocket: WebSocket) -> _Connection | None:
        """Register a websocket under *org_id*. Returns the Connection or None if full."""
        async with self._lock:
            if len(self._all) >= MAX_CONNECTIONS:
                logger.warning("ws_max_connections_reached", count=len(self._all))
                return None
            conn = _Connection(websocket=websocket, org_id=org_id)
            self._by_org[org_id].add(conn)
            self._all.add(conn)
            logger.info("ws_subscribed", org_id=org_id, total=len(self._all))
            return conn

    async def unsubscribe(self, conn: _Connection) -> None:
        """Remove a connection from all registries."""
        async with self._lock:
            self._by_org.get(conn.org_id, set()).discard(conn)
            if conn.org_id in self._by_org and not self._by_org[conn.org_id]:
                del self._by_org[conn.org_id]
            self._all.discard(conn)
        logger.info("ws_unsubscribed", org_id=conn.org_id, total=len(self._all))

    # -- Broadcast --------------------------------------------------------

    def _envelope(
        self,
        event_type: RealtimeEventType | str,
        data: dict[str, Any],
        org_id: str,
    ) -> dict[str, Any]:
        et = event_type.value if isinstance(event_type, RealtimeEventType) else event_type
        return {"type": et, "org_id": org_id, "data": data, "ts": time.time()}

    async def broadcast_to_org(
        self,
        org_id: str,
        event_type: RealtimeEventType | str | dict[str, Any],
        data: dict[str, Any] | None = None,
    ) -> int:
        """Send an event to all connections subscribed under *org_id*.

        Two calling conventions are supported:

        - ``broadcast_to_org(org_id, event_type, data)`` — build envelope
        - ``broadcast_to_org(org_id, {"type": ..., "data": ...})`` — pass
          a pre-built event dict. Missing keys are filled in.

        Returns the number of successful deliveries.
        """
        envelope = self._coerce_envelope(event_type, data, org_id)
        targets = list(self._by_org.get(org_id, set()))
        return await self._fanout(targets, envelope)

    async def broadcast_to_all(
        self,
        event_type: RealtimeEventType | str | dict[str, Any],
        data: dict[str, Any] | None = None,
    ) -> int:
        """Admin-only: broadcast to every active connection."""
        envelope = self._coerce_envelope(event_type, data, _ADMIN_CHANNEL)
        targets = list(self._all)
        return await self._fanout(targets, envelope)

    def _coerce_envelope(
        self,
        event_type: RealtimeEventType | str | dict[str, Any],
        data: dict[str, Any] | None,
        org_id: str,
    ) -> dict[str, Any]:
        """Accept either (type, data) or a single event-dict form."""
        if isinstance(event_type, dict):
            ev = dict(event_type)
            ev.setdefault("type", "unknown")
            ev.setdefault("org_id", org_id)
            ev.setdefault("data", {})
            ev.setdefault("ts", time.time())
            return ev
        return self._envelope(event_type, data or {}, org_id)

    async def _fanout(
        self,
        targets: list[_Connection],
        envelope: dict[str, Any],
    ) -> int:
        delivered = 0
        dead: list[_Connection] = []
        for conn in targets:
            ws = conn.websocket
            if ws.client_state != WebSocketState.CONNECTED:
                dead.append(conn)
                continue
            try:
                await ws.send_json(envelope)
                delivered += 1
            except Exception as exc:
                logger.debug("ws_send_failed", error=str(exc))
                dead.append(conn)
        for conn in dead:
            await self.unsubscribe(conn)
        return delivered

    # -- Heartbeat / cleanup ---------------------------------------------

    def touch(self, conn: _Connection) -> None:
        """Mark a connection as alive (called on pong)."""
        conn.last_pong = time.time()

    async def cleanup_stale(self) -> int:
        """Evict connections that haven't responded within the heartbeat timeout."""
        now = time.time()
        stale: list[_Connection] = [c for c in list(self._all) if c.is_stale(now)]
        for conn in stale:
            with contextlib.suppress(Exception):
                await conn.websocket.close(code=4002, reason="Heartbeat timeout")
            await self.unsubscribe(conn)
        if stale:
            logger.info("ws_stale_evicted", count=len(stale))
        return len(stale)

    async def start_cleanup_task(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return

        async def _loop() -> None:
            while True:
                try:
                    await asyncio.sleep(HEARTBEAT_INTERVAL_S)
                    await self.cleanup_stale()
                except asyncio.CancelledError:
                    break
                except Exception as exc:  # pragma: no cover — defensive
                    logger.warning("ws_cleanup_error", error=str(exc))

        self._cleanup_task = asyncio.create_task(_loop())

    async def stop_cleanup_task(self) -> None:
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._cleanup_task
            self._cleanup_task = None

    # -- Introspection ----------------------------------------------------

    @property
    def active_connections(self) -> int:
        return len(self._all)

    def connections_for_org(self, org_id: str) -> int:
        return len(self._by_org.get(org_id, set()))

    def get_stats(self) -> dict[str, Any]:
        """Return connection statistics for monitoring / debug endpoints."""
        per_org = {org_id: len(conns) for org_id, conns in self._by_org.items()}
        return {
            "total_connections": len(self._all),
            "org_count": len(self._by_org),
            "per_org": per_org,
            "max_connections": MAX_CONNECTIONS,
        }


# --- Module-level singleton --------------------------------------------------

_broadcaster: Broadcaster | None = None


def get_broadcaster() -> Broadcaster:
    """Get the process-wide Broadcaster singleton."""
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = Broadcaster()
    return _broadcaster


def reset_broadcaster() -> None:
    """Test helper — reset the singleton between test cases."""
    global _broadcaster
    _broadcaster = None

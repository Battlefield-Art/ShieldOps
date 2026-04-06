"""Unified real-time WebSocket endpoint for the ShieldOps dashboard.

Authenticates a client via JWT query parameter, registers the connection
with the process-wide :class:`Broadcaster`, and services heartbeats until
the client disconnects or the heartbeat timeout fires.

Event envelope is defined in :mod:`shieldops.api.ws.broadcaster`. This
module only handles the connection lifecycle — all event publication
flows through the broadcaster so producers never touch sockets directly.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any

import structlog
from fastapi import APIRouter, Query
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from shieldops.api.auth.service import decode_token
from shieldops.api.ws.broadcaster import (
    HEARTBEAT_INTERVAL_S,
    HEARTBEAT_TIMEOUT_S,
    Broadcaster,
    get_broadcaster,
)

logger = structlog.get_logger()

router = APIRouter()


# --- Auth helpers -----------------------------------------------------------


def _extract_org_id(payload: dict[str, Any]) -> str:
    """Derive an org_id from a JWT payload.

    Tokens today don't always carry ``org_id`` explicitly — fall back to
    ``tenant_id`` then ``sub`` so single-tenant deployments still isolate
    per-user.
    """
    for key in ("org_id", "tenant_id", "org", "sub"):
        value = payload.get(key)
        if value:
            return str(value)
    return "__unknown__"


async def _authenticate(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    return decode_token(token)


# --- WebSocket route --------------------------------------------------------


@router.websocket("/ws/realtime")
async def ws_realtime(
    websocket: WebSocket,
    token: str | None = Query(default=None),
) -> None:
    """Unified real-time event stream.

    Event types delivered: ``agent_status_change``, ``new_situation``,
    ``firewall_event``, ``metric_update``, ``agent_run_complete``.
    """
    payload = await _authenticate(token)
    if payload is None:
        await websocket.accept()
        await websocket.close(code=4001, reason="Authentication required")
        return

    org_id = _extract_org_id(payload)

    await websocket.accept()
    broadcaster = get_broadcaster()
    conn = await broadcaster.subscribe(org_id, websocket)
    if conn is None:
        await websocket.close(code=4003, reason="Max connections reached")
        return

    # Send a hello message so the client can confirm subscription
    await websocket.send_json(
        {
            "type": "subscribed",
            "org_id": org_id,
            "data": {"user_id": payload.get("sub")},
            "ts": time.time(),
        }
    )

    heartbeat_task: asyncio.Task[None] = asyncio.create_task(
        _heartbeat_loop(websocket, broadcaster, conn)
    )

    try:
        while True:
            msg = await websocket.receive_text()
            # Treat any inbound frame as a liveness signal; parse optional
            # pong messages to explicitly refresh last_pong.
            broadcaster.touch(conn)
            if msg in ("pong", "ping"):
                continue
    except WebSocketDisconnect:
        logger.info("ws_realtime_disconnect", org_id=org_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("ws_realtime_error", org_id=org_id, error=str(exc))
    finally:
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await heartbeat_task
        await broadcaster.unsubscribe(conn)
        if websocket.client_state == WebSocketState.CONNECTED:
            with contextlib.suppress(Exception):
                await websocket.close()


async def _heartbeat_loop(
    websocket: WebSocket,
    broadcaster: Broadcaster,
    conn: Any,
) -> None:
    """Send periodic pings and evict the connection if it goes stale."""
    while True:
        try:
            await asyncio.sleep(HEARTBEAT_INTERVAL_S)
        except asyncio.CancelledError:
            return

        if websocket.client_state != WebSocketState.CONNECTED:
            return

        try:
            await websocket.send_json({"type": "ping", "ts": time.time()})
        except Exception:
            return

        if conn.is_stale():
            logger.info("ws_realtime_stale_evict")
            with contextlib.suppress(Exception):
                await websocket.close(code=4002, reason="Heartbeat timeout")
            return


@router.get("/ws/realtime/stats")
async def ws_realtime_stats() -> dict[str, Any]:
    """Debug endpoint exposing broadcaster stats.

    Auth is enforced at the middleware layer — this endpoint is safe to
    leave unauthenticated for readiness probes if desired, but production
    should route through the admin auth dependency.
    """
    broadcaster = get_broadcaster()
    return {
        "heartbeat_interval_s": HEARTBEAT_INTERVAL_S,
        "heartbeat_timeout_s": HEARTBEAT_TIMEOUT_S,
        **broadcaster.get_stats(),
    }

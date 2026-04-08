"""WebSocket routes for real-time event streaming.

RFC #242 PR-3 (#257) — migrated off the legacy module-level
``ConnectionManager`` singleton onto :class:`shieldops.api.ws.core.Hub`.
Each route now claims the hub via ``Depends(get_ws_hub)``; producers
fan out by publishing to the same topic name the route subscribes to.

Live forwarding through the Hub's drain task into the attached
Starlette socket lands in RFC #242 PR-5 (#259) — that PR adds the
``StarletteTransport`` adapter and rewires these routes to call
``hub.attach()`` directly. Until then the route keeps the socket alive
locally; the producer-side migration is what this PR ships.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from shieldops.api.auth.service import decode_token
from shieldops.api.ws.composition import get_ws_hub
from shieldops.api.ws.core import Hub

logger = structlog.get_logger()

router = APIRouter()


async def _authenticate_ws(websocket: WebSocket, token: str | None) -> dict[str, Any] | None:
    """Validate JWT from query parameter. Returns payload or None."""
    if not token:
        return None
    return decode_token(token)


async def _hold_open(websocket: WebSocket, channel: str) -> None:
    """Accept the connection and hold it until the client disconnects.

    TODO(RFC #242 PR-5 / #259): replace with ``hub.attach(...)`` once
    the StarletteTransport adapter lands.
    """
    await websocket.accept()
    logger.info("ws_connected", channel=channel)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("ws_disconnected", channel=channel)


@router.websocket("/ws/events")
async def ws_global_events(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    hub: Hub = Depends(get_ws_hub),
) -> None:
    """Global event stream — broadcasts all investigation/remediation events."""
    payload = await _authenticate_ws(websocket, token)
    if payload is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    _ = hub  # retained for the dependency contract; PR-5 wires drain
    await _hold_open(websocket, channel="global")


@router.websocket("/ws/investigations/{investigation_id}")
async def ws_investigation_events(
    websocket: WebSocket,
    investigation_id: str,
    token: str | None = Query(default=None),
    hub: Hub = Depends(get_ws_hub),
) -> None:
    """Stream events for a specific investigation."""
    payload = await _authenticate_ws(websocket, token)
    if payload is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    _ = hub
    await _hold_open(websocket, channel=f"investigation:{investigation_id}")


@router.websocket("/ws/remediations/{remediation_id}")
async def ws_remediation_events(
    websocket: WebSocket,
    remediation_id: str,
    token: str | None = Query(default=None),
    hub: Hub = Depends(get_ws_hub),
) -> None:
    """Stream events for a specific remediation."""
    payload = await _authenticate_ws(websocket, token)
    if payload is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    _ = hub
    await _hold_open(websocket, channel=f"remediation:{remediation_id}")


@router.websocket("/ws/vulnerabilities")
async def ws_vulnerability_events(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    hub: Hub = Depends(get_ws_hub),
) -> None:
    """Stream vulnerability lifecycle events."""
    payload = await _authenticate_ws(websocket, token)
    if payload is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    _ = hub
    await _hold_open(websocket, channel="vulnerabilities")


@router.websocket("/ws/security-chat/{session_id}")
async def ws_security_chat(
    websocket: WebSocket,
    session_id: str,
    token: str | None = Query(default=None),
    hub: Hub = Depends(get_ws_hub),
) -> None:
    """WebSocket for AI security chat sessions."""
    payload = await _authenticate_ws(websocket, token)
    if payload is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    _ = hub
    await _hold_open(websocket, channel=f"security-chat:{session_id}")

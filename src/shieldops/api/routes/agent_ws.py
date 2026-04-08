"""WebSocket handler for real-time agent task step updates.

RFC #242 PR-3 (#257) — migrated off the local ``ConnectionManager`` and
onto :class:`shieldops.api.ws.core.Hub`.  Routes now reach the installed
hub via ``Depends(get_ws_hub)``; producers (notify_step_update) publish
via the hub by topic ``agent_task:<task_id>``.

NOTE: full Starlette transport wiring (so live events fan out to the
attached websocket sockets through the Hub's drain task) is RFC #242
PR-5 (#259).  Until that lands the route still keeps the connection
alive via a local receive-loop and the producer-side path is the
critical migration target this PR ships.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from shieldops.api.auth.service import decode_token
from shieldops.api.ws.composition import get_ws_hub
from shieldops.api.ws.core import Event, Hub

logger = structlog.get_logger()

router = APIRouter()


def _agent_task_topic(task_id: str) -> str:
    """Stable topic naming for agent task updates."""
    return f"agent_task:{task_id}"


async def notify_step_update(
    task_id: str,
    step_id: str,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    """Publish an agent step update via the WebSocket Hub.

    Background task helper — there is no FastAPI request context here,
    so we reach the installed hub via :func:`get_ws_hub` directly. The
    Hub raises ``RuntimeError`` if no hub is installed (e.g. when called
    outside an app lifespan), which is the right failure mode.
    """
    event_type = "step_update"
    if status == "complete":
        event_type = "task_complete"
    elif status == "approval_required":
        event_type = "approval_required"
    elif status == "error":
        event_type = "error"

    message: dict[str, Any] = {
        "event": event_type,
        "step_id": step_id,
        "status": status,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if result is not None:
        message["result"] = result
    if error is not None:
        message["error"] = error

    logger.info(
        "agent_step_update",
        task_id=task_id,
        step_id=step_id,
        event_kind=event_type,
        status=status,
    )
    try:
        hub = get_ws_hub()
    except RuntimeError:
        # Hub not installed (e.g. tests / out-of-app callers). Step
        # updates are best-effort — log and move on.
        logger.debug("agent_step_update_no_hub", task_id=task_id)
        return
    await hub.publish(_agent_task_topic(task_id), Event(kind=event_type, data=message))


async def _authenticate_ws(websocket: WebSocket, token: str | None) -> dict[str, Any] | None:
    """Validate JWT from query parameter. Returns payload or None."""
    if not token:
        return None
    return decode_token(token)


@router.websocket("/ws/agent-tasks/{task_id}")
async def ws_agent_task(
    websocket: WebSocket,
    task_id: str,
    token: str | None = Query(default=None),
    hub: Hub = Depends(get_ws_hub),
) -> None:
    """Stream real-time step updates for an agent task execution.

    The hub dependency is wired so this route claims the standard
    ``Depends(get_ws_hub)`` contract. Live forwarding from the hub's
    drain task into this websocket happens once the StarletteTransport
    adapter lands in PR-5 (#259); until then the route keeps the
    connection alive and producers can still publish to the topic.

    Sends JSON messages with the schema::

        {
            "event": "step_update" | "task_complete" | "approval_required" | "error",
            "step_id": "<str>",
            "status": "<str>",
            "result": { ... },      // optional
            "error": "<str>",       // optional
            "timestamp": "<iso8601>"
        }
    """
    payload = await _authenticate_ws(websocket, token)
    if payload is None:
        await websocket.close(code=4001, reason="Authentication required")
        return

    # TODO(RFC #242 PR-5 / #259): replace this local accept+receive loop
    # with hub.attach() once StarletteTransport lands. The producer-side
    # is already migrated; only the wire-side needs the transport adapter.
    _ = hub  # explicitly retain the dependency for clarity
    await websocket.accept()
    logger.info("agent_ws_connected", task_id=task_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("agent_ws_disconnected", task_id=task_id)

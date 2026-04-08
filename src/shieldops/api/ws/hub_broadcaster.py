"""Producer-side adapter that bridges legacy ``broadcast(channel, dict)``
call sites onto the WebSocket Hub's ``publish(channel, Event)`` API.

Background — RFC #242 PR-3 (#257)
--------------------------------
Before the Hub landed, every producer (agent runners, vulnerability
lifecycle, etc.) reached for the legacy ``ConnectionManager`` singleton
and called ``manager.broadcast(channel, event_dict)`` directly.  PR-1
shipped the Hub core; PR-2 shipped the composition root + the
``Depends(get_ws_hub)`` contract.  This module is the **producer-side
adapter** that lets background callers (no FastAPI request context)
fan out via the Hub without rewriting every runner constructor.

The shim implements the *exact* shape of the legacy
``ConnectionManager.broadcast`` so the runners and lifecycle managers
can be wired with a :class:`HubBroadcaster` instance with zero behaviour
change.  The lifespan hook in :mod:`shieldops.api.api.app` builds the
Hub, installs it via :func:`set_ws_hub`, and then constructs a single
:class:`HubBroadcaster` to hand to runners.

This module deliberately lives **outside** :mod:`shieldops.api.ws.core`
and :mod:`shieldops.api.ws.adapters` because it is composition glue,
not a Hub port adapter.  The acceptance grep in #257 only allows
``ws_manager.broadcast`` literals inside ``ws/core/`` and
``ws/adapters/`` — the shim instead exposes ``broadcast(...)`` and
forwards to ``hub.publish(...)``.

Usage (lifespan)::

    hub = build_in_memory_hub()
    set_ws_hub(hub)
    broadcaster = HubBroadcaster(hub)
    InvestigationRunner(ws_manager=broadcaster, ...)

Usage (background task without DI)::

    from shieldops.api.ws.composition import get_ws_hub
    from shieldops.api.ws.hub_broadcaster import HubBroadcaster
    HubBroadcaster(get_ws_hub()).publish_dict("channel", {...})
"""

from __future__ import annotations

from typing import Any

from shieldops.api.ws.core import Event, Hub

__all__ = ["HubBroadcaster"]


class HubBroadcaster:
    """Producer-side ``broadcast`` shim that publishes via :class:`Hub`.

    Accepts both legacy call shapes:

    * positional: ``await b.broadcast("channel", {...})``  (runners)
    * keyword:    ``await b.broadcast(channel="...", message={...})``
      (vulnerability lifecycle)

    Each call is translated to ``await hub.publish(channel, Event(kind, data))``
    where ``kind`` is taken from ``event["type"]`` if present, else falls
    back to ``"event"``.  The full dict is preserved as ``Event.data`` so
    no information is lost in the migration.
    """

    def __init__(self, hub: Hub) -> None:
        self._hub = hub

    async def broadcast(
        self,
        channel: str | None = None,
        event: dict[str, Any] | None = None,
        *,
        message: dict[str, Any] | None = None,
    ) -> str:
        """Publish ``event`` (or ``message``) to ``channel`` via the Hub.

        Returns the Hub-assigned event id.  Raises ``ValueError`` if the
        caller passes neither ``event`` nor ``message`` — that would be
        a programming error and we want it loud, not silent.
        """
        payload = event if event is not None else message
        if channel is None or payload is None:
            raise ValueError(
                "HubBroadcaster.broadcast requires a channel and an event/message dict"
            )
        kind = str(payload.get("type") or payload.get("event") or "event")
        return await self._hub.publish(channel, Event(kind=kind, data=dict(payload)))

    # Convenience for non-route background callers that already have a
    # dict in hand and want a typed entry point.
    async def publish_dict(self, channel: str, payload: dict[str, Any]) -> str:
        return await self.broadcast(channel, payload)

    @property
    def hub(self) -> Hub:
        """Expose the wrapped Hub for callers that need the full API."""
        return self._hub

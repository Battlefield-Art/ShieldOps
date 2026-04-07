"""WebSocket Hub core — pure logic, no I/O, no framework dependencies.

See RFC #242 (ghantakiran/ShieldOps#242) for the full design. The core
depends only on the injected ports in :mod:`shieldops.api.ws.core.ports`:
``Transport``, ``Buffer``, ``Authenticator``, ``Clock``, ``Logger``,
``Tracer``. Production wires real adapters at ``app.py`` lifespan; tests
wire in-memory adapters from :mod:`shieldops.api.ws.adapters`.

This package has **zero imports** from ``fastapi``, ``starlette``,
``redis``, ``time``, ``structlog``, ``opentelemetry`` — enforced by
ruff rule ``SHOP-003`` once the rule lands.
"""

from __future__ import annotations

from shieldops.api.ws.core.events import (
    BufferedEvent,
    Event,
    HubConfig,
    Principal,
    Subscription,
)
from shieldops.api.ws.core.hub import AuthError, Hub
from shieldops.api.ws.core.ports import (
    Authenticator,
    Buffer,
    Clock,
    Logger,
    Tracer,
    Transport,
)

__all__ = [
    "AuthError",
    "Authenticator",
    "Buffer",
    "BufferedEvent",
    "Clock",
    "Event",
    "Hub",
    "HubConfig",
    "Logger",
    "Principal",
    "Subscription",
    "Tracer",
    "Transport",
]

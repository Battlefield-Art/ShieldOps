"""Adapters for the WebSocket Hub core ports.

Production wiring (real SDKs, real time, real network) and test wiring
(in-memory, manual clock, canned responses) both live here. The core
in :mod:`shieldops.api.ws.core` never imports from the real adapters —
tests can inject any subset without any framework dependency.

PR-1 (RFC #242) ships only the in-memory / test adapters. Production
adapters (``StarletteTransport``, ``JwtAuthenticator``, ``SystemClock``,
``StructlogLogger``, ``OtelTracer``) land in PR-2 once the core is
proven by the contract test.
"""

from __future__ import annotations

from shieldops.api.ws.adapters.inmemory_buffer import InMemoryBuffer
from shieldops.api.ws.adapters.inmemory_transport import InMemoryTransport
from shieldops.api.ws.adapters.manual_clock import ManualClock
from shieldops.api.ws.adapters.null_logger import NullLogger
from shieldops.api.ws.adapters.null_tracer import NullTracer
from shieldops.api.ws.adapters.static_token_authenticator import (
    StaticTokenAuthenticator,
)

__all__ = [
    "InMemoryBuffer",
    "InMemoryTransport",
    "ManualClock",
    "NullLogger",
    "NullTracer",
    "StaticTokenAuthenticator",
]

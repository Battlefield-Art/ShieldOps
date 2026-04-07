"""Port Protocols for the WebSocket Hub core.

Every cross-boundary dependency the Hub needs is expressed as a
:class:`typing.Protocol` here. Production wires real adapters
(Starlette WebSocket, Redis Streams, JWT, ``time.time``, structlog,
OpenTelemetry); tests wire the in-memory adapters in
:mod:`shieldops.api.ws.adapters`.

The Hub core has **zero imports** from real SDKs — only from this
module. Ruff rule ``SHOP-003`` enforces that once it lands.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from shieldops.api.ws.core.events import BufferedEvent, Principal


@runtime_checkable
class Transport(Protocol):
    """Wire-level adapter for sending bytes to a connection."""

    async def send(self, conn_id: str, payload: bytes) -> None: ...
    async def close(self, conn_id: str, code: int = 1000) -> None: ...
    def is_open(self, conn_id: str) -> bool: ...


@runtime_checkable
class Buffer(Protocol):
    """Per-channel event ring buffer for replay-on-reconnect."""

    async def append(
        self,
        channel: str,
        event_id: str,
        payload: bytes,
        ts: float,
    ) -> None: ...

    def since(
        self,
        channel: str,
        since_id: str | None,
    ) -> AsyncIterator[BufferedEvent]:
        """Return events newer than ``since_id`` (exclusive).

        Contract:
        - ``since_id=None`` yields the entire current window.
        - If ``since_id`` is older than the buffer's earliest remaining
          event (evicted), yield the entire current window so the client
          can self-recover.
        """
        ...

    async def trim(
        self,
        channel: str,
        max_age_s: float,
        max_len: int,
    ) -> None: ...


@runtime_checkable
class Authenticator(Protocol):
    """Validates a connection token and resolves the ``Principal``."""

    async def authenticate(self, token: str, channel: str) -> Principal:
        """Raise :class:`AuthError` on invalid token."""
        ...


@runtime_checkable
class Clock(Protocol):
    """Injectable clock for deterministic tests."""

    def now(self) -> datetime: ...
    async def sleep(self, seconds: float) -> None: ...


@runtime_checkable
class Logger(Protocol):
    """structlog-compatible subset — bind + level methods only."""

    def bind(self, **kw: Any) -> Logger: ...
    def info(self, msg: str, **kw: Any) -> None: ...
    def warning(self, msg: str, **kw: Any) -> None: ...
    def error(self, msg: str, **kw: Any) -> None: ...


@runtime_checkable
class Tracer(Protocol):
    """OpenTelemetry-compatible span context manager."""

    def span(self, name: str, **attrs: Any) -> AbstractContextManager[Any]: ...

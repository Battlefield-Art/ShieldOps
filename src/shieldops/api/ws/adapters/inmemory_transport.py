"""In-memory ``Transport`` adapter — no network, no Starlette.

Satisfies :class:`shieldops.api.ws.core.ports.Transport`. Used by the
contract tests in ``tests/unit/api/ws/test_hub.py`` to drive the Hub
through its full lifecycle without a real WebSocket or FastAPI app.

Tests inspect sent payloads via :meth:`sent` — the transport records
every successful send in a per-connection list so assertions can check
ordering, count, and content.
"""

from __future__ import annotations

import json
from typing import Any


class InMemoryTransport:
    """In-memory transport. ``register`` + ``send`` + ``close`` + ``is_open``.

    Usage pattern (from a test)::

        transport = InMemoryTransport()
        transport.register("c1")          # "connect" the fake WebSocket
        await hub.attach(conn_id="c1", ...)
        await hub.publish(...)
        sent = transport.sent("c1")       # list[dict] decoded from JSON
    """

    def __init__(self) -> None:
        self._sent: dict[str, list[dict[str, Any]]] = {}
        self._open: set[str] = set()
        self._close_codes: dict[str, int] = {}

    # -- Test setup --------------------------------------------------------

    def register(self, conn_id: str) -> None:
        """Mark a connection as open. Analogous to Starlette's ``ws.accept()``."""
        self._open.add(conn_id)
        self._sent.setdefault(conn_id, [])

    # -- Transport protocol -----------------------------------------------

    async def send(self, conn_id: str, payload: bytes) -> None:
        if conn_id not in self._open:
            raise RuntimeError(f"connection {conn_id} not open")
        # Decode the canonical JSON envelope so tests can assert on
        # structured content without redoing the bytes → dict dance.
        self._sent.setdefault(conn_id, []).append(json.loads(payload))

    async def close(self, conn_id: str, code: int = 1000) -> None:
        self._open.discard(conn_id)
        self._close_codes[conn_id] = code

    def is_open(self, conn_id: str) -> bool:
        return conn_id in self._open

    # -- Test inspection ---------------------------------------------------

    def sent(self, conn_id: str) -> list[dict[str, Any]]:
        """All envelopes sent to ``conn_id`` in order. Empty list if none."""
        return list(self._sent.get(conn_id, []))

    def close_code(self, conn_id: str) -> int | None:
        return self._close_codes.get(conn_id)

"""Per-connection bounded send queue with overflow policy (#5).

Problem: a single slow WebSocket client can stall fan-out to every other
client if the broadcaster awaits ``send_json`` inline.

Solution: each connection gets its own :class:`BoundedSender` with a bounded
``asyncio.Queue`` and a background task that drains it. Overflow is handled
by either dropping the oldest pending message or disconnecting the client.
"""

from __future__ import annotations

import asyncio
import contextlib
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class OverflowPolicy(StrEnum):
    DROP_OLDEST = "drop_oldest"
    DISCONNECT = "disconnect"


class SenderClosed(Exception):
    """Raised when enqueue is called on a closed sender."""


class BoundedSender:
    """Per-WebSocket bounded send queue with a background drain task."""

    def __init__(
        self,
        websocket: Any,
        *,
        max_pending: int,
        overflow: OverflowPolicy = OverflowPolicy.DROP_OLDEST,
    ) -> None:
        if max_pending <= 0:
            raise ValueError("max_pending must be > 0")
        self._ws = websocket
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_pending)
        self._overflow = overflow
        self._drain_task: asyncio.Task[None] | None = None
        self._closed = False
        self._dropped_count = 0

    async def start(self) -> None:
        """Start the background drain task."""
        if self._drain_task is not None:
            return
        self._drain_task = asyncio.create_task(self._drain_loop())

    async def enqueue(self, message: dict[str, Any]) -> None:
        """Enqueue a message for delivery. Applies overflow policy if full."""
        if self._closed:
            raise SenderClosed("sender has been stopped")

        if self._queue.full():
            if self._overflow == OverflowPolicy.DROP_OLDEST:
                # Drop oldest and push newest
                try:
                    _ = self._queue.get_nowait()
                    self._dropped_count += 1
                    logger.debug("ws.bounded_sender.drop_oldest", dropped=self._dropped_count)
                except asyncio.QueueEmpty:
                    pass
                self._queue.put_nowait(message)
                return
            elif self._overflow == OverflowPolicy.DISCONNECT:
                logger.warning(
                    "ws.bounded_sender.disconnect_on_overflow",
                    max_pending=self._queue.maxsize,
                )
                await self.stop(reason="back-pressure overflow")
                raise SenderClosed("disconnected due to back-pressure overflow")

        self._queue.put_nowait(message)

    async def flush(self) -> None:
        """Wait until the queue is drained (for tests)."""
        while not self._queue.empty():
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)  # allow in-flight send to finish

    async def stop(self, *, reason: str = "stopped") -> None:
        """Stop the drain task and close the websocket."""
        if self._closed:
            return
        self._closed = True
        if self._drain_task is not None:
            self._drain_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._drain_task
            self._drain_task = None
        with contextlib.suppress(Exception):
            await self._ws.close(code=1011, reason=reason)

    @property
    def dropped_count(self) -> int:
        return self._dropped_count

    async def _drain_loop(self) -> None:
        while not self._closed:
            try:
                message = await self._queue.get()
            except asyncio.CancelledError:
                break
            try:
                await self._ws.send_json(message)
            except Exception as exc:  # pragma: no cover — defensive
                logger.debug("ws.bounded_sender.send_failed", error=str(exc))
                break

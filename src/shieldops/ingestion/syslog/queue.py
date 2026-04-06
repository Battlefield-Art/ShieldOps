"""Bounded ingestion queue with drop-oldest backpressure for syslog listeners."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from shieldops.ingestion.pipeline import process_event
from shieldops.ingestion.syslog.parser import parse_rfc5424

logger = structlog.get_logger()

# Type for a function that consumes one parsed syslog event.
EventHandler = Callable[[dict[str, Any], str], Awaitable[str]]


class SyslogIngestQueue:
    """Bounded asyncio queue that drops the oldest item when full.

    A single background worker drains the queue and calls
    ``shieldops.ingestion.pipeline.process_event`` for each message. This
    decouples socket receive loops from the storage layer so slow writes
    cannot stall the listeners.
    """

    def __init__(
        self,
        org_id: str = "default",
        max_size: int = 10_000,
        handler: EventHandler | None = None,
    ) -> None:
        self.org_id = org_id
        self.max_size = max_size
        self._queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue(maxsize=max_size)
        self._worker_task: asyncio.Task[None] | None = None
        self._running = False
        self._handler: EventHandler = handler or self._default_handler
        self.dropped_count = 0
        self.processed_count = 0
        self.failed_count = 0

    async def _default_handler(self, event: dict[str, Any], org_id: str) -> str:
        return await process_event(event, source_provider="syslog", org_id=org_id)

    async def put(self, raw_line: str, transport: str) -> bool:
        """Enqueue a raw syslog line. Drops oldest if full.

        Returns True if enqueued, False if a drop occurred.
        """
        if self._queue.full():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                self.dropped_count += 1
                logger.warning(
                    "syslog.queue_full_drop_oldest",
                    dropped_count=self.dropped_count,
                    max_size=self.max_size,
                )
            except asyncio.QueueEmpty:
                pass
            await self._queue.put((raw_line, transport))
            return False
        await self._queue.put((raw_line, transport))
        return True

    async def start(self) -> None:
        """Start the background drain worker."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._drain())
        logger.info("syslog.queue_started", max_size=self.max_size, org_id=self.org_id)

    async def stop(self) -> None:
        """Stop the drain worker and wait for it to finish."""
        if not self._running:
            return
        self._running = False
        if self._worker_task is not None:
            self._worker_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._worker_task
            self._worker_task = None
        logger.info(
            "syslog.queue_stopped",
            processed=self.processed_count,
            dropped=self.dropped_count,
            failed=self.failed_count,
        )

    async def _drain(self) -> None:
        while self._running:
            try:
                raw_line, transport = await self._queue.get()
            except asyncio.CancelledError:
                return
            try:
                parsed = parse_rfc5424(raw_line)
                parsed["_transport"] = transport
                await self._handler(parsed, self.org_id)
                self.processed_count += 1
            except Exception as exc:
                self.failed_count += 1
                logger.warning(
                    "syslog.event_failed",
                    error=str(exc),
                    transport=transport,
                    line_prefix=raw_line[:80],
                )
            finally:
                self._queue.task_done()

    def stats(self) -> dict[str, int]:
        return {
            "queue_size": self._queue.qsize(),
            "max_size": self.max_size,
            "processed": self.processed_count,
            "dropped": self.dropped_count,
            "failed": self.failed_count,
        }

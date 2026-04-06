"""Async UDP listener for RFC 5424 syslog messages."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import structlog

from shieldops.ingestion.syslog.queue import SyslogIngestQueue

logger = structlog.get_logger()


class _SyslogDatagramProtocol(asyncio.DatagramProtocol):
    """Datagram protocol that forwards each packet as one syslog message."""

    def __init__(self, queue: SyslogIngestQueue) -> None:
        self.queue = queue
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        try:
            line = data.decode("utf-8", errors="replace").rstrip("\r\n")
        except Exception as exc:
            logger.warning("syslog.udp_decode_error", peer=str(addr), error=str(exc))
            return
        if not line:
            return
        # Fire-and-forget — UDP has no backpressure to the sender.
        asyncio.create_task(self.queue.put(line, transport="udp"))

    def error_received(self, exc: Exception) -> None:
        logger.warning("syslog.udp_error", error=str(exc))


class SyslogUDPListener:
    """Async UDP server for RFC 5424 syslog messages."""

    def __init__(
        self,
        queue: SyslogIngestQueue,
        host: str = "0.0.0.0",  # noqa: S104  # nosec B104 — syslog receivers bind to all interfaces
        port: int = 6514,
    ) -> None:
        self.queue = queue
        self.host = host
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _SyslogDatagramProtocol | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogDatagramProtocol(self.queue),
            local_addr=(self.host, self.port),
        )
        self._transport = transport  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]
        logger.info("syslog.udp_listener_started", host=self.host, port=self.port)

    async def stop(self) -> None:
        if self._transport is not None:
            with contextlib.suppress(Exception):
                self._transport.close()
            self._transport = None
            self._protocol = None
            logger.info("syslog.udp_listener_stopped", host=self.host, port=self.port)

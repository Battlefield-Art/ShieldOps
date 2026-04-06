"""Lifecycle manager for syslog TCP + UDP listeners.

Keeps a single ``SyslogIngestQueue`` shared between both transports so the
backpressure budget is enforced globally. Listeners are never started on
import — callers must invoke ``start_listeners`` explicitly (typically
from the FastAPI lifespan).
"""

from __future__ import annotations

import structlog

from shieldops.ingestion.syslog.queue import EventHandler, SyslogIngestQueue
from shieldops.ingestion.syslog.tcp_listener import SyslogTCPListener
from shieldops.ingestion.syslog.udp_listener import SyslogUDPListener

logger = structlog.get_logger()


class SyslogListenerManager:
    """Owns the queue + TCP/UDP listeners as a single unit."""

    def __init__(
        self,
        org_id: str = "default",
        host: str = "0.0.0.0",  # noqa: S104  # nosec B104 — syslog receivers bind to all interfaces
        tcp_port: int = 6514,
        udp_port: int = 6514,
        queue_size: int = 10_000,
        enable_tcp: bool = True,
        enable_udp: bool = True,
        handler: EventHandler | None = None,
    ) -> None:
        self.queue = SyslogIngestQueue(org_id=org_id, max_size=queue_size, handler=handler)
        self.host = host
        self.tcp: SyslogTCPListener | None = (
            SyslogTCPListener(self.queue, host=host, port=tcp_port) if enable_tcp else None
        )
        self.udp: SyslogUDPListener | None = (
            SyslogUDPListener(self.queue, host=host, port=udp_port) if enable_udp else None
        )
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        await self.queue.start()
        if self.tcp is not None:
            await self.tcp.start()
        if self.udp is not None:
            await self.udp.start()
        self._running = True
        logger.info("syslog.manager_started", host=self.host)

    async def stop(self) -> None:
        if not self._running:
            return
        if self.tcp is not None:
            await self.tcp.stop()
        if self.udp is not None:
            await self.udp.stop()
        await self.queue.stop()
        self._running = False
        logger.info("syslog.manager_stopped")

    def stats(self) -> dict[str, int]:
        return self.queue.stats()


_manager: SyslogListenerManager | None = None


def get_manager() -> SyslogListenerManager | None:
    """Return the currently running manager, if any."""
    return _manager


async def start_listeners(
    org_id: str = "default",
    host: str = "0.0.0.0",  # noqa: S104  # nosec B104
    tcp_port: int = 6514,
    udp_port: int = 6514,
    queue_size: int = 10_000,
    enable_tcp: bool = True,
    enable_udp: bool = True,
    handler: EventHandler | None = None,
) -> SyslogListenerManager:
    """Start (or return) the process-wide syslog listener manager."""
    global _manager
    if _manager is not None and _manager._running:
        return _manager
    _manager = SyslogListenerManager(
        org_id=org_id,
        host=host,
        tcp_port=tcp_port,
        udp_port=udp_port,
        queue_size=queue_size,
        enable_tcp=enable_tcp,
        enable_udp=enable_udp,
        handler=handler,
    )
    await _manager.start()
    return _manager


async def stop_listeners() -> None:
    """Stop the process-wide syslog listener manager, if running."""
    global _manager
    if _manager is None:
        return
    await _manager.stop()
    _manager = None

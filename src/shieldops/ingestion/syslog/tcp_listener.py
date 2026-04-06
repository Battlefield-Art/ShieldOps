"""Async TCP listener for RFC 5424 syslog messages.

Supports both newline-framed (non-transparent) and octet-counted framing
per RFC 6587. Each inbound message is pushed into a bounded
``SyslogIngestQueue`` which drains into the ingestion pipeline.
"""

from __future__ import annotations

import asyncio
import contextlib

import structlog

from shieldops.ingestion.syslog.queue import SyslogIngestQueue

logger = structlog.get_logger()

_MAX_LINE_BYTES = 64 * 1024  # RFC 5425 recommends 8KB minimum; we allow 64KB.


class SyslogTCPListener:
    """Async TCP server that reads RFC 5424 syslog messages."""

    def __init__(
        self,
        queue: SyslogIngestQueue,
        host: str = "0.0.0.0",  # noqa: S104  # nosec B104 — syslog receivers bind to all interfaces
        port: int = 6514,
    ) -> None:
        self.queue = queue
        self.host = host
        self.port = port
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, host=self.host, port=self.port
        )
        logger.info("syslog.tcp_listener_started", host=self.host, port=self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
            logger.info("syslog.tcp_listener_stopped", host=self.host, port=self.port)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.debug("syslog.tcp_client_connected", peer=str(peer))
        try:
            while not reader.at_eof():
                line = await self._read_message(reader)
                if line is None:
                    break
                if not line:
                    continue
                await self.queue.put(line, transport="tcp")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("syslog.tcp_client_error", peer=str(peer), error=str(exc))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug("syslog.tcp_client_disconnected", peer=str(peer))

    async def _read_message(self, reader: asyncio.StreamReader) -> str | None:
        """Read one syslog message using octet-counted or newline framing.

        Returns None when the peer closes the connection, else the decoded
        message (without trailing newline / length prefix).
        """
        # Peek first byte to detect octet-counted framing (RFC 6587).
        first = await reader.read(1)
        if not first:
            return None

        if first.isdigit():
            # Octet-counted: <digits> SP MSG
            length_buf = bytearray(first)
            while True:
                ch = await reader.read(1)
                if not ch:
                    return None
                if ch == b" ":
                    break
                if not ch.isdigit():
                    # Not actually octet-counted — fall back to treating
                    # what we have plus the rest of the line as newline-framed.
                    rest = await reader.readline()
                    return (
                        (bytes(length_buf) + ch + rest)
                        .decode("utf-8", errors="replace")
                        .rstrip("\r\n")
                    )
                length_buf += ch
                if len(length_buf) > 10:  # sanity — message length unreasonably large
                    return None
            try:
                length = int(length_buf)
            except ValueError:
                return None
            if length <= 0 or length > _MAX_LINE_BYTES:
                return None
            payload = await reader.readexactly(length)
            return payload.decode("utf-8", errors="replace")

        # Newline-framed (non-transparent)
        rest = await reader.readline()
        line_bytes = first + rest
        if len(line_bytes) > _MAX_LINE_BYTES:
            logger.warning("syslog.tcp_oversize_line", size=len(line_bytes))
            return ""
        return line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")

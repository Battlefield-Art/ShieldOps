"""Packet Inspector Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import PacketInspectorToolkit

logger = structlog.get_logger()


class PacketInspectorRunner:
    """Runs the Packet Inspector agent workflow."""

    def __init__(
        self,
        pcap_client: Any | None = None,
        tls_client: Any | None = None,
        threat_feed_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PacketInspectorToolkit(
            pcap_client=pcap_client,
            tls_client=tls_client,
            threat_feed_client=threat_feed_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("packet_inspector_runner.init")

    async def inspect(
        self,
        tenant_id: str,
        packets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute the full packet inspection workflow.

        Args:
            tenant_id: Tenant identifier.
            packets: List of packet dicts with keys:
                src_ip, dst_ip, src_port, dst_port,
                protocol, raw_hex, direction, flags.

        Returns:
            Final state dict with analyses, TLS checks,
            threats, and statistics.
        """
        packets = packets or []
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "packets": packets,
            "reasoning_chain": [],
        }

        logger.info(
            "packet_inspector_runner.inspect",
            request_id=request_id,
            tenant_id=tenant_id,
            packet_count=len(packets),
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "packet_inspector_runner.inspect.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist inspection results."""
        if self._repository:
            await self._repository.save_inspection_run(result)

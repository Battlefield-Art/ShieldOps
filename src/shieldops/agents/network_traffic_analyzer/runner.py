"""Network Traffic Analyzer Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import NetworkTrafficAnalyzerToolkit

logger = structlog.get_logger()


class NetworkTrafficAnalyzerRunner:
    """Runs the Network Traffic Analyzer agent workflow."""

    def __init__(
        self,
        flow_source: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = NetworkTrafficAnalyzerToolkit(
            flow_source=flow_source,
            threat_intel=threat_intel,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info(
            "network_traffic_analyzer_runner.init",
        )

    async def analyze(
        self,
        tenant_id: str,
        raw_flows: (list[dict[str, Any]] | None) = None,
    ) -> dict[str, Any]:
        """Execute the full network traffic analysis.

        Args:
            tenant_id: Tenant identifier.
            raw_flows: List of flow dicts with keys:
                src_ip, dst_ip, src_port, dst_port,
                protocol, bytes_sent, bytes_received,
                packets, duration_ms.

        Returns:
            Final state dict with anomalies,
            threats, enforcements, and statistics.
        """
        raw_flows = raw_flows or []
        request_id = f"nta-{uuid.uuid4().hex[:12]}"

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "raw_flows": raw_flows,
            "reasoning_chain": [],
        }

        logger.info(
            "nta_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            flow_count=len(raw_flows),
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(
                initial_state,  # type: ignore[arg-type]
            )
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "nta_runner.analyze.error",
                request_id=request_id,
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist analysis results."""
        if self._repository:
            await self._repository.save_analysis_run(
                result,
            )

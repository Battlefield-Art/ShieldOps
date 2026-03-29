"""Bandwidth Anomaly Detector Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import BandwidthAnomalyDetectorToolkit

logger = structlog.get_logger()


class BandwidthAnomalyDetectorRunner:
    """Runs the Bandwidth Anomaly Detector agent workflow."""

    def __init__(
        self,
        netflow_client: Any | None = None,
        firewall_client: Any | None = None,
        alert_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BandwidthAnomalyDetectorToolkit(
            netflow_client=netflow_client,
            firewall_client=firewall_client,
            alert_client=alert_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("bandwidth_anomaly_detector_runner.init")

    async def detect(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full bandwidth anomaly detection."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "bandwidth_anomaly_detector_runner.detect",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("bandwidth_anomaly_detector_runner.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist bandwidth anomaly results."""
        if self._repository:
            await self._repository.save_bandwidth_report(result)

"""Anomaly Detector Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AnomalyDetectorToolkit

logger = structlog.get_logger()


class AnomalyDetectorRunner:
    """Runs the Anomaly Detector agent workflow."""

    def __init__(
        self,
        metric_client: Any | None = None,
        log_client: Any | None = None,
        trace_client: Any | None = None,
        alert_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AnomalyDetectorToolkit(
            metric_client=metric_client,
            log_client=log_client,
            trace_client=trace_client,
            alert_client=alert_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("anomaly_detector_runner.init")

    async def detect(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full anomaly detection workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "anomaly_detector_runner.detect",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("anomaly_detector_runner.detect.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist anomaly detection results."""
        if self._repository:
            await self._repository.save_anomaly_report(result)

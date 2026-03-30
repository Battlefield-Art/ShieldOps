"""Log Anomaly Detector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.log_anomaly_detector.graph import (
    create_log_anomaly_detector_graph,
)
from shieldops.agents.log_anomaly_detector.models import (
    LogAnomalyDetectorState,
)
from shieldops.agents.log_anomaly_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.log_anomaly_detector.tools import (
    LogAnomalyDetectorToolkit,
)

logger = structlog.get_logger()


class LogAnomalyDetectorRunner:
    """Runner for the Log Anomaly Detector Agent."""

    def __init__(
        self,
        log_client: Any | None = None,
        pattern_engine: Any | None = None,
        anomaly_engine: Any | None = None,
        correlation_engine: Any | None = None,
        alert_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = LogAnomalyDetectorToolkit(
            log_client=log_client,
            pattern_engine=pattern_engine,
            anomaly_engine=anomaly_engine,
            correlation_engine=correlation_engine,
            alert_engine=alert_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_log_anomaly_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, LogAnomalyDetectorState] = {}
        logger.info("lad_runner.initialized")

    async def detect(
        self,
        request_id: str,
        tenant_id: str = "",
        detect_config: dict[str, Any] | None = None,
    ) -> LogAnomalyDetectorState:
        """Run log anomaly detection workflow."""
        sid = f"lad-{uuid4().hex[:12]}"
        initial = LogAnomalyDetectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            detect_config=detect_config or {},
        )

        logger.info(
            "lad_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "log_anomaly_detector",
                    },
                },
            )
            final = LogAnomalyDetectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "lad_runner.completed",
                session_id=sid,
                records=final.total_records,
                anomalies=len(final.detected_anomalies),
                alerts=len(final.prioritized_alerts),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "lad_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = LogAnomalyDetectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                detect_config=detect_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> LogAnomalyDetectorState | None:
        """Retrieve a previous detection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all detection results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_records": s.total_records,
                "patterns": len(s.log_patterns),
                "new_patterns": s.new_pattern_count,
                "anomalies": len(s.detected_anomalies),
                "correlations": len(s.correlated_events),
                "alerts": len(s.prioritized_alerts),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

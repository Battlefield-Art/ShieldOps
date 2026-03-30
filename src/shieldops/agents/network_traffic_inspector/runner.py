"""Network Traffic Inspector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_traffic_inspector.graph import (
    create_network_traffic_inspector_graph,
)
from shieldops.agents.network_traffic_inspector.models import (
    NetworkTrafficInspectorState,
)
from shieldops.agents.network_traffic_inspector.nodes import (
    set_toolkit,
)
from shieldops.agents.network_traffic_inspector.tools import (
    NetworkTrafficInspectorToolkit,
)

logger = structlog.get_logger()


class NetworkTrafficInspectorRunner:
    """Runner for the Network Traffic Inspector Agent."""

    def __init__(
        self,
        packet_capture: Any | None = None,
        protocol_analyzer: Any | None = None,
        anomaly_engine: Any | None = None,
        threat_classifier: Any | None = None,
        alert_manager: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = NetworkTrafficInspectorToolkit(
            packet_capture=packet_capture,
            protocol_analyzer=protocol_analyzer,
            anomaly_engine=anomaly_engine,
            threat_classifier=threat_classifier,
            alert_manager=alert_manager,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_network_traffic_inspector_graph()
        self._app = graph.compile()
        self._results: dict[str, NetworkTrafficInspectorState] = {}
        logger.info("nti_runner.initialized")

    async def inspect(
        self,
        request_id: str,
        tenant_id: str = "",
        capture_config: dict[str, Any] | None = None,
    ) -> NetworkTrafficInspectorState:
        """Run network traffic inspection workflow."""
        sid = f"nti-{uuid4().hex[:12]}"
        initial = NetworkTrafficInspectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            capture_config=capture_config or {},
        )

        logger.info(
            "nti_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "network_traffic_inspector",
                    },
                },
            )
            final = NetworkTrafficInspectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "nti_runner.completed",
                session_id=sid,
                flows=len(final.captured_flows),
                anomalies=len(final.detected_anomalies),
                threats=len(final.threat_classifications),
                alerts=len(final.generated_alerts),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "nti_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = NetworkTrafficInspectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                capture_config=capture_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> NetworkTrafficInspectorState | None:
        """Retrieve a previous inspection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all inspection results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_flows": len(s.captured_flows),
                "total_bytes": s.total_bytes,
                "anomalies": len(s.detected_anomalies),
                "critical_threats": s.critical_threat_count,
                "alerts": len(s.generated_alerts),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

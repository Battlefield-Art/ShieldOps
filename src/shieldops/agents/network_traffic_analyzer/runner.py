"""Network Traffic Analyzer runner — entry point for traffic analysis."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_traffic_analyzer.graph import (
    create_network_traffic_analyzer_graph,
)
from shieldops.agents.network_traffic_analyzer.models import (
    NetworkTrafficAnalyzerState,
)
from shieldops.agents.network_traffic_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.network_traffic_analyzer.tools import (
    NetworkTrafficAnalyzerToolkit,
)

logger = structlog.get_logger()


class NetworkTrafficAnalyzerRunner:
    """Runner for the Network Traffic Analyzer Agent."""

    def __init__(
        self,
        flow_source: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._toolkit = NetworkTrafficAnalyzerToolkit(
            flow_source=flow_source,
            threat_intel=threat_intel,
        )
        set_toolkit(self._toolkit)
        graph = create_network_traffic_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, NetworkTrafficAnalyzerState] = {}
        logger.info(
            "network_traffic_analyzer_runner.initialized",
        )

    async def execute(
        self,
        tenant_id: str,
        raw_flows: list[dict[str, Any]] | None = None,
    ) -> NetworkTrafficAnalyzerState:
        """Run the network traffic analyzer workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant
                isolation.
            raw_flows: List of raw flow dicts with keys like
                src_ip, dst_ip, src_port, dst_port, protocol,
                bytes_sent, bytes_received, packets.

        Returns:
            Final NetworkTrafficAnalyzerState with anomalies,
            threats, protocol analyses, and correlations.
        """
        request_id = f"nta-{uuid4().hex[:12]}"

        initial_state = NetworkTrafficAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            raw_flows=raw_flows or [],
        )

        logger.info(
            "network_traffic_analyzer_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            flows=len(initial_state.raw_flows),
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "network_traffic_analyzer",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = NetworkTrafficAnalyzerState.model_validate(
                final_state_dict,
            )
            self._results[request_id] = final_state

            logger.info(
                "network_traffic_analyzer_runner.completed",
                request_id=request_id,
                flows=len(final_state.flows),
                anomalies=len(final_state.anomalies),
                threats=len(final_state.threats),
                protocols=len(final_state.protocol_analyses),
                correlations=len(final_state.correlations),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "network_traffic_analyzer_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = NetworkTrafficAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                raw_flows=raw_flows or [],
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> NetworkTrafficAnalyzerState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all execution results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "flows": len(state.flows),
                "anomalies": len(state.anomalies),
                "threats": len(state.threats),
                "protocols": len(state.protocol_analyses),
                "correlations": len(state.correlations),
                "current_step": state.current_step,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

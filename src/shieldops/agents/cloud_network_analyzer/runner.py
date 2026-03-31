"""Cloud Network Analyzer Agent runner — entry point
for cloud network topology and security analysis."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_network_analyzer.graph import (
    create_cloud_network_analyzer_graph,
)
from shieldops.agents.cloud_network_analyzer.models import (
    CloudNetworkAnalyzerState,
    CloudProvider,
)
from shieldops.agents.cloud_network_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_network_analyzer.tools import (
    CloudNetworkAnalyzerToolkit,
)

logger = structlog.get_logger()


class CloudNetworkAnalyzerRunner:
    """Runner for the Cloud Network Analyzer Agent."""

    def __init__(
        self,
        cloud_connector: Any | None = None,
        route_analyzer: Any | None = None,
        segmentation_engine: Any | None = None,
        exposure_scanner: Any | None = None,
        compliance_engine: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudNetworkAnalyzerToolkit(
            cloud_connector=cloud_connector,
            route_analyzer=route_analyzer,
            segmentation_engine=segmentation_engine,
            exposure_scanner=exposure_scanner,
            compliance_engine=compliance_engine,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_network_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudNetworkAnalyzerState] = {}
        logger.info("cna_runner.initialized")

    async def analyze(
        self,
        target_provider: str = "aws",
        target_vpcs: list[str] | None = None,
        scan_scope: dict[str, Any] | None = None,
        compliance_framework: str = "",
        tenant_id: str = "",
    ) -> CloudNetworkAnalyzerState:
        """Run a cloud network analysis session."""
        request_id = f"cna-{uuid4().hex[:12]}"

        initial_state = CloudNetworkAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_provider=CloudProvider(target_provider),
            target_vpcs=target_vpcs or [],
            scan_scope=scan_scope or {},
            compliance_framework=compliance_framework,
        )

        logger.info(
            "cna_runner.starting",
            request_id=request_id,
            provider=target_provider,
            vpc_count=len(target_vpcs or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_network_analyzer",
                    },
                },
            )
            final = CloudNetworkAnalyzerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cna_runner.completed",
                request_id=request_id,
                resources=final.total_resources,
                exposures=final.exposure_count,
                critical=final.critical_exposures,
                segmentation=final.segmentation_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cna_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudNetworkAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CloudNetworkAnalyzerState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "provider": s.target_provider.value,
                "resources": s.total_resources,
                "exposures": s.exposure_count,
                "critical": s.critical_exposures,
                "segmentation": s.segmentation_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

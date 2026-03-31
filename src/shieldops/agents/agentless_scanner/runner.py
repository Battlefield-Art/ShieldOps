"""Agentless Scanner Agent runner — entry point for
executing API-based cloud security scans."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.agentless_scanner.graph import (
    create_agentless_scanner_graph,
)
from shieldops.agents.agentless_scanner.models import (
    AgentlessScannerState,
    CloudProvider,
)
from shieldops.agents.agentless_scanner.nodes import (
    set_toolkit,
)
from shieldops.agents.agentless_scanner.tools import (
    AgentlessScannerToolkit,
)

logger = structlog.get_logger()


class AgentlessScannerRunner:
    """Runner for the Agentless Scanner Agent."""

    def __init__(
        self,
        cloud_client: Any | None = None,
        vuln_database: Any | None = None,
        config_benchmarks: Any | None = None,
        exposure_analyzer: Any | None = None,
        risk_scorer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AgentlessScannerToolkit(
            cloud_client=cloud_client,
            vuln_database=vuln_database,
            config_benchmarks=config_benchmarks,
            exposure_analyzer=exposure_analyzer,
            risk_scorer=risk_scorer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_agentless_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, AgentlessScannerState] = {}
        logger.info("as_runner.initialized")

    async def scan(
        self,
        scan_name: str,
        target_providers: list[str] | None = None,
        target_regions: list[str] | None = None,
        scan_scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> AgentlessScannerState:
        """Run an agentless cloud security scan."""
        request_id = f"as-{uuid4().hex[:12]}"

        providers = [
            CloudProvider(p)
            for p in (target_providers or [])
            if p in CloudProvider.__members__.values()
        ]

        initial_state = AgentlessScannerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            target_providers=providers,
            target_regions=target_regions or [],
            scan_scope=scan_scope or {},
        )

        logger.info(
            "as_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            providers=len(providers),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "agentless_scanner",
                    },
                },
            )
            final = AgentlessScannerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "as_runner.completed",
                request_id=request_id,
                total_assets=final.total_assets,
                total_findings=final.total_findings,
                critical=final.critical_findings,
                coverage=final.scan_coverage,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "as_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AgentlessScannerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_name=scan_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> AgentlessScannerState | None:
        """Retrieve a cached scan result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_assets": s.total_assets,
                "total_findings": s.total_findings,
                "critical": s.critical_findings,
                "coverage": s.scan_coverage,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

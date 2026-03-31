"""Security Metric Dashboard Agent runner — entry point
for executing security metrics workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_metric_dashboard.graph import (
    create_security_metric_dashboard_graph,
)
from shieldops.agents.security_metric_dashboard.models import (
    SecurityMetricDashboardState,
)
from shieldops.agents.security_metric_dashboard.nodes import (
    set_toolkit,
)
from shieldops.agents.security_metric_dashboard.tools import (
    SecurityMetricDashboardToolkit,
)

logger = structlog.get_logger()


class SecurityMetricDashboardRunner:
    """Runner for the Security Metric Dashboard Agent."""

    def __init__(
        self,
        siem_connector: Any | None = None,
        vuln_scanner: Any | None = None,
        edr_connector: Any | None = None,
        compliance_engine: Any | None = None,
        benchmark_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityMetricDashboardToolkit(
            siem_connector=siem_connector,
            vuln_scanner=vuln_scanner,
            edr_connector=edr_connector,
            compliance_engine=compliance_engine,
            benchmark_db=benchmark_db,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_metric_dashboard_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityMetricDashboardState] = {}
        logger.info("smd_runner.initialized")

    async def compute(
        self,
        tenant_id: str = "",
        period: str = "30d",
        context: dict[str, Any] | None = None,
    ) -> SecurityMetricDashboardState:
        """Execute a security metrics computation."""
        request_id = f"smd-{uuid4().hex[:12]}"

        initial_state = SecurityMetricDashboardState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "smd_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            period=period,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("security_metric_dashboard"),
                    },
                },
            )
            final = SecurityMetricDashboardState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "smd_runner.completed",
                request_id=request_id,
                kpi_count=final.kpi_count,
                failing=len(final.failing_kpis),
                gaps=len(final.coverage_gaps),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "smd_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityMetricDashboardState(
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
    ) -> SecurityMetricDashboardState | None:
        """Retrieve a cached metrics result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all metrics results as summaries."""
        return [
            {
                "request_id": rid,
                "kpi_count": s.kpi_count,
                "failing": len(s.failing_kpis),
                "gaps": len(s.coverage_gaps),
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

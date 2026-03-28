"""Dashboard Aggregator Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_dashboard_aggregator.graph import (
    create_security_dashboard_aggregator_graph,
)
from shieldops.agents.security_dashboard_aggregator.models import (
    SecurityDashboardAggregatorState,
)
from shieldops.agents.security_dashboard_aggregator.nodes import (
    set_toolkit,
)
from shieldops.agents.security_dashboard_aggregator.tools import (
    SecurityDashboardAggregatorToolkit,
)

logger = structlog.get_logger()


class SecurityDashboardAggregatorRunner:
    """Runner for the Dashboard Aggregator Agent."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        metric_store: Any | None = None,
        incident_store: Any | None = None,
        finding_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityDashboardAggregatorToolkit(
            agent_registry=agent_registry,
            metric_store=metric_store,
            incident_store=incident_store,
            finding_store=finding_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_dashboard_aggregator_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityDashboardAggregatorState] = {}
        logger.info("dashboard_aggregator_runner.initialized")

    async def aggregate(
        self,
        tenant_id: str,
    ) -> SecurityDashboardAggregatorState:
        """Run dashboard aggregation."""
        sid = f"dash-{uuid4().hex[:12]}"
        initial = SecurityDashboardAggregatorState(
            tenant_id=tenant_id,
            request_id=sid,
        )

        logger.info(
            "dashboard_aggregator_runner.starting",
            session_id=sid,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": ("security_dashboard_aggregator"),
                    }
                },
            )
            final = SecurityDashboardAggregatorState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "dashboard_aggregator_runner.completed",
                session_id=sid,
                metrics=len(final.agent_metrics),
                agents=final.agents_reporting,
                kpis=len(final.kpis),
                anomalies=len(final.anomalies),
                score=(final.dashboard_data.overall_score),
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "dashboard_aggregator_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err = SecurityDashboardAggregatorState(
                tenant_id=tenant_id,
                request_id=sid,
                error=str(e),
            )
            self._results[sid] = err
            return err

    def get_result(
        self,
        session_id: str,
    ) -> SecurityDashboardAggregatorState | None:
        """Retrieve a stored result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all aggregation summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "metrics": len(s.agent_metrics),
                "agents": s.agents_reporting,
                "kpis": len(s.kpis),
                "anomalies": len(s.anomalies),
                "score": (s.dashboard_data.overall_score),
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

"""Incident Cost Tracker Agent runner — entry point
for executing incident cost analysis."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_cost_tracker.graph import (
    create_incident_cost_tracker_graph,
)
from shieldops.agents.incident_cost_tracker.models import (
    IncidentCostTrackerState,
    IncidentSeverity,
)
from shieldops.agents.incident_cost_tracker.nodes import (
    set_toolkit,
)
from shieldops.agents.incident_cost_tracker.tools import (
    IncidentCostTrackerToolkit,
)

logger = structlog.get_logger()


class IncidentCostTrackerRunner:
    """Runner for the Incident Cost Tracker Agent."""

    def __init__(
        self,
        incident_manager: Any | None = None,
        cost_database: Any | None = None,
        regulatory_engine: Any | None = None,
        insurance_provider: Any | None = None,
        benchmark_service: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IncidentCostTrackerToolkit(
            incident_manager=incident_manager,
            cost_database=cost_database,
            regulatory_engine=regulatory_engine,
            insurance_provider=insurance_provider,
            benchmark_service=benchmark_service,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_incident_cost_tracker_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentCostTrackerState] = {}
        logger.info("ict_runner.initialized")

    async def analyze(
        self,
        incident_id: str = "",
        incident_type: str = "",
        severity: str = "medium",
        affected_systems: list[str] | None = None,
        records_exposed: int = 0,
        downtime_hours: float = 0.0,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> IncidentCostTrackerState:
        """Run an incident cost analysis."""
        request_id = f"ict-{uuid4().hex[:12]}"

        sev = IncidentSeverity.MEDIUM
        if severity in IncidentSeverity.__members__.values():
            sev = IncidentSeverity(severity)

        initial_state = IncidentCostTrackerState(
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            incident_type=incident_type,
            severity=sev,
            affected_systems=affected_systems or [],
            records_exposed=records_exposed,
            downtime_hours=downtime_hours,
            scope=scope or {},
        )

        logger.info(
            "ict_runner.starting",
            request_id=request_id,
            incident_id=incident_id,
            severity=severity,
            records=records_exposed,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "incident_cost_tracker",
                    },
                },
            )
            final = IncidentCostTrackerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "ict_runner.completed",
                request_id=request_id,
                direct=final.total_direct_usd,
                indirect=final.total_indirect_usd,
                regulatory=final.total_regulatory_usd,
                grand_total=final.grand_total_usd,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ict_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IncidentCostTrackerState(
                request_id=request_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> IncidentCostTrackerState | None:
        """Retrieve a cached cost analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all cost analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "incident_id": s.incident_id,
                "severity": s.severity.value,
                "direct_usd": s.total_direct_usd,
                "indirect_usd": s.total_indirect_usd,
                "regulatory_usd": s.total_regulatory_usd,
                "grand_total_usd": s.grand_total_usd,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

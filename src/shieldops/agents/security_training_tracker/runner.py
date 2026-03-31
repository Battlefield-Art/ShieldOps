"""Security Training Tracker Agent runner — entry point
for training completion and effectiveness tracking."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_training_tracker.graph import (
    create_security_training_tracker_graph,
)
from shieldops.agents.security_training_tracker.models import (
    SecurityTrainingTrackerState,
)
from shieldops.agents.security_training_tracker.nodes import (
    set_toolkit,
)
from shieldops.agents.security_training_tracker.tools import (
    SecurityTrainingTrackerToolkit,
)

logger = structlog.get_logger()


class SecurityTrainingTrackerRunner:
    """Runner for the Security Training Tracker Agent."""

    def __init__(
        self,
        lms_client: Any | None = None,
        hr_system: Any | None = None,
        compliance_engine: Any | None = None,
        phishing_sim: Any | None = None,
        metrics_store: Any | None = None,
        notification_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityTrainingTrackerToolkit(
            lms_client=lms_client,
            hr_system=hr_system,
            compliance_engine=compliance_engine,
            phishing_sim=phishing_sim,
            metrics_store=metrics_store,
            notification_engine=notification_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_training_tracker_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityTrainingTrackerState] = {}
        logger.info("stt_runner.initialized")

    async def track(
        self,
        org_units: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        compliance_frameworks: list[str] | None = None,
        tenant_id: str = "",
    ) -> SecurityTrainingTrackerState:
        """Run training tracking and effectiveness analysis."""
        request_id = f"stt-{uuid4().hex[:12]}"

        initial_state = SecurityTrainingTrackerState(
            request_id=request_id,
            tenant_id=tenant_id,
            org_units=org_units or [],
            scope=scope or {},
            compliance_frameworks=compliance_frameworks or [],
        )

        logger.info(
            "stt_runner.starting",
            request_id=request_id,
            org_units=len(org_units or []),
            frameworks=len(compliance_frameworks or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_training_tracker",
                    },
                },
            )
            final = SecurityTrainingTrackerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "stt_runner.completed",
                request_id=request_id,
                requirements=final.total_requirements,
                completion=final.completion_rate,
                overdue=final.overdue_count,
                gaps=final.gap_count,
            )
            return final

        except Exception as e:
            logger.error(
                "stt_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityTrainingTrackerState(
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
    ) -> SecurityTrainingTrackerState | None:
        """Retrieve a cached tracking result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all tracking results as summaries."""
        return [
            {
                "request_id": rid,
                "total_requirements": s.total_requirements,
                "completion_rate": s.completion_rate,
                "overdue_count": s.overdue_count,
                "gap_count": s.gap_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

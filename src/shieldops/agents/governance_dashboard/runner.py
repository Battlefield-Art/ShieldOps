"""Governance Dashboard Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.governance_dashboard.graph import (
    create_governance_dashboard_graph,
)
from shieldops.agents.governance_dashboard.models import (
    GovernanceDashboardState,
)
from shieldops.agents.governance_dashboard.nodes import (
    set_toolkit,
)
from shieldops.agents.governance_dashboard.tools import (
    GovernanceDashboardToolkit,
)

logger = structlog.get_logger()


class GovernanceDashboardRunner:
    """Runner for the Governance Dashboard Agent."""

    def __init__(
        self,
        metrics_service: Any | None = None,
        policy_service: Any | None = None,
    ) -> None:
        self._toolkit = GovernanceDashboardToolkit(
            metrics_service=metrics_service,
            policy_service=policy_service,
        )
        set_toolkit(self._toolkit)
        graph = create_governance_dashboard_graph()
        self._app = graph.compile()
        self._results: dict[str, GovernanceDashboardState] = {}
        logger.info(
            "governance_dashboard_runner.initialized",
        )

    async def execute(
        self,
        tenant_id: str,
    ) -> GovernanceDashboardState:
        """Run the governance dashboard workflow."""
        session_id = f"gd-{uuid4().hex[:12]}"
        initial = GovernanceDashboardState(
            request_id=session_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "governance_dashboard.starting",
            session_id=session_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "governance_dashboard",
                    }
                },
            )
            final = GovernanceDashboardState.model_validate(
                result,
            )
            self._results[session_id] = final

            logger.info(
                "governance_dashboard.completed",
                session_id=session_id,
                metrics=len(final.metrics),
                assessments=len(final.policy_assessments),
                risk_scores=len(final.risk_scores),
                posture=final.overall_posture,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "governance_dashboard.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = GovernanceDashboardState(
                request_id=session_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> GovernanceDashboardState | None:
        """Retrieve a stored result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all governance dashboard run summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "metrics": len(s.metrics),
                "assessments": len(s.policy_assessments),
                "risk_scores": len(s.risk_scores),
                "overall_posture": s.overall_posture,
                "stage": s.stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

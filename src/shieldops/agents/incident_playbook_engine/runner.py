"""Incident Playbook Engine runner — entry point for executing playbook workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_playbook_engine.graph import (
    create_incident_playbook_engine_graph,
)
from shieldops.agents.incident_playbook_engine.models import (
    IncidentPlaybookEngineState,
)
from shieldops.agents.incident_playbook_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.incident_playbook_engine.tools import (
    IncidentPlaybookEngineToolkit,
)

logger = structlog.get_logger()


class IncidentPlaybookEngineRunner:
    """Runner for the Incident Playbook Engine."""

    def __init__(
        self,
        playbook_db: Any | None = None,
        outcome_db: Any | None = None,
    ) -> None:
        self._toolkit = IncidentPlaybookEngineToolkit(
            playbook_db=playbook_db,
            outcome_db=outcome_db,
        )
        set_toolkit(self._toolkit)
        graph = create_incident_playbook_engine_graph(
            playbook_db=playbook_db,
            outcome_db=outcome_db,
        )
        self._app = graph.compile()
        self._results: dict[str, IncidentPlaybookEngineState] = {}
        logger.info("ipe_runner.initialized")

    async def run(
        self,
        tenant_id: str,
        alert_title: str,
        alert_description: str,
        alert_source: str = "",
        alert_severity: str = "medium",
        alert_indicators: list[str] | None = None,
        affected_assets: list[str] | None = None,
    ) -> IncidentPlaybookEngineState:
        """Run the incident playbook engine workflow.

        Args:
            tenant_id: Tenant identifier.
            alert_title: Title of the triggering alert.
            alert_description: Description of the alert.
            alert_source: Source system of the alert.
            alert_severity: Initial severity assessment.
            alert_indicators: IOCs or indicators from alert.
            affected_assets: List of affected asset IDs.

        Returns:
            Final IncidentPlaybookEngineState with full
            execution results.
        """
        request_id = f"ipe-{uuid4().hex[:12]}"

        initial_state = IncidentPlaybookEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            alert_title=alert_title,
            alert_description=alert_description,
            alert_source=alert_source,
            alert_severity=alert_severity,
            alert_indicators=alert_indicators or [],
            affected_assets=affected_assets or [],
        )

        logger.info(
            "ipe_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            alert_title=alert_title,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "incident_playbook_engine",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = IncidentPlaybookEngineState.model_validate(final_dict)
            self._results[request_id] = final_state

            logger.info(
                "ipe_runner.completed",
                request_id=request_id,
                category=final_state.classification.category.value,
                playbook=final_state.selected_playbook.name,
                success=final_state.outcome.success,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "ipe_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IncidentPlaybookEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                alert_title=alert_title,
                alert_description=alert_description,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> IncidentPlaybookEngineState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all execution results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "category": s.classification.category.value,
                "severity": s.classification.severity,
                "playbook": s.selected_playbook.name,
                "status": s.execution.status.value,
                "success": s.outcome.success,
                "residual_risk": s.outcome.residual_risk,
                "current_step": s.current_step,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

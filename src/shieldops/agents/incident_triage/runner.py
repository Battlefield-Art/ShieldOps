"""Incident Triage Agent runner — entry point for executing triage workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_triage.graph import create_incident_triage_graph
from shieldops.agents.incident_triage.models import (
    IncidentTriageState,
    IncomingIncident,
)
from shieldops.agents.incident_triage.nodes import set_toolkit
from shieldops.agents.incident_triage.tools import IncidentTriageToolkit

logger = structlog.get_logger()


class IncidentTriageRunner:
    """Runner for the Incident Triage Agent."""

    def __init__(
        self,
        incident_db: Any | None = None,
        change_db: Any | None = None,
        oncall_service: Any | None = None,
    ) -> None:
        self._toolkit = IncidentTriageToolkit(
            incident_db=incident_db,
            change_db=change_db,
            oncall_service=oncall_service,
        )
        set_toolkit(self._toolkit)
        graph = create_incident_triage_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentTriageState] = {}
        logger.info("incident_triage_runner.initialized")

    async def triage(
        self,
        tenant_id: str,
        incidents: list[dict[str, Any]] | None = None,
    ) -> IncidentTriageState:
        """Run the incident triage workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            incidents: List of raw incident dicts to triage. Each dict should contain
                keys like title, description, source, raw_severity, alerts,
                affected_services.

        Returns:
            Final IncidentTriageState with classifications, enrichments,
            routing decisions, and stats.
        """
        request_id = f"triage-{uuid4().hex[:12]}"

        # Convert raw dicts to IncomingIncident models
        incoming: list[IncomingIncident] = []
        for raw in incidents or []:
            incoming.append(
                IncomingIncident(
                    **{k: v for k, v in raw.items() if k in IncomingIncident.model_fields}
                )
            )

        initial_state = IncidentTriageState(
            request_id=request_id,
            tenant_id=tenant_id,
            incoming_incidents=incoming,
        )

        logger.info(
            "incident_triage_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            incident_count=len(incoming),
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "incident_triage",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = IncidentTriageState.model_validate(final_state_dict)
            self._results[request_id] = final_state

            logger.info(
                "incident_triage_runner.completed",
                request_id=request_id,
                incident_count=len(final_state.incoming_incidents),
                classifications=len(final_state.classifications),
                routing_decisions=len(final_state.routing_decisions),
                deduplicated=final_state.deduplicated_count,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "incident_triage_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IncidentTriageState(
                request_id=request_id,
                tenant_id=tenant_id,
                incoming_incidents=incoming,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> IncidentTriageState | None:
        """Retrieve a previous triage result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all triage results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "incident_count": len(state.incoming_incidents),
                "classifications": len(state.classifications),
                "routing_decisions": len(state.routing_decisions),
                "deduplicated": state.deduplicated_count,
                "current_step": state.current_step,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

"""Incident Communicator Agent runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_communicator.graph import (
    create_incident_communicator_graph,
)
from shieldops.agents.incident_communicator.models import (
    IncidentCommunicatorState,
)
from shieldops.agents.incident_communicator.nodes import set_toolkit
from shieldops.agents.incident_communicator.tools import (
    IncidentCommunicatorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentCommunicatorRunner:
    """Runner for the Incident Communicator Agent."""

    def __init__(
        self,
        notification_service: Any | None = None,
        stakeholder_directory: Any | None = None,
    ) -> None:
        self._toolkit = IncidentCommunicatorToolkit(
            notification_service=notification_service,
            stakeholder_directory=stakeholder_directory,
        )
        set_toolkit(self._toolkit)
        graph = create_incident_communicator_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentCommunicatorState] = {}
        logger.info("incident_communicator_runner.initialized")

    @enforced("incident_communicator")
    async def execute(
        self,
        tenant_id: str,
        incident_id: str,
        severity: str = "medium",
    ) -> IncidentCommunicatorState:
        """Run the incident communication workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            incident_id: The incident to communicate about.
            severity: Incident severity (critical/high/medium/low/informational).

        Returns:
            Final IncidentCommunicatorState with notification results.
        """
        request_id = f"comm-{uuid4().hex[:12]}"

        initial_state = IncidentCommunicatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )

        logger.info(
            "incident_communicator_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            severity=severity,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "incident_communicator",
                        "tenant_id": tenant_id,
                        "severity": severity,
                    },
                },
            )
            final_state = IncidentCommunicatorState.model_validate(
                final_state_dict,
            )
            self._results[request_id] = final_state

            logger.info(
                "incident_communicator_runner.completed",
                request_id=request_id,
                notifications=len(final_state.notifications),
                ack_count=final_state.ack_count,
                channels=final_state.channels_used,
            )
            return final_state

        except Exception as e:
            logger.error(
                "incident_communicator_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IncidentCommunicatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                error=str(e),
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> IncidentCommunicatorState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all communication results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "incident_id": state.incident_id,
                "notifications": len(state.notifications),
                "ack_count": state.ack_count,
                "channels_used": state.channels_used,
                "stage": state.stage.value,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

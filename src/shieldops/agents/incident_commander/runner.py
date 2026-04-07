"""Incident Commander Agent runner — entry point for coordinating incident response.

Takes an incident context, constructs the LangGraph, runs it end-to-end,
and returns the completed incident commander state.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_commander.graph import create_incident_commander_graph
from shieldops.agents.incident_commander.models import (
    IncidentCommanderState,
    IncidentContext,
)
from shieldops.agents.incident_commander.nodes import set_toolkit
from shieldops.agents.incident_commander.tools import IncidentCommanderToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentCommanderRunner:
    """Runs incident commander coordination workflows.

    Usage:
        runner = IncidentCommanderRunner(
            incident_client=incident_mgmt,
            agent_dispatcher=dispatcher,
        )
        result = await runner.run(
            incident_context=IncidentContext(
                alert_id="ALT-001",
                service="payment-api",
                environment="production",
                severity=SeverityLevel.SEV2,
                description="Payment API latency spike",
            )
        )
    """

    def __init__(
        self,
        incident_client: Any = None,
        agent_dispatcher: Any = None,
        escalation_client: Any = None,
        runbook_client: Any = None,
    ) -> None:
        self._toolkit = IncidentCommanderToolkit(
            incident_client=incident_client,
            agent_dispatcher=agent_dispatcher,
            escalation_client=escalation_client,
            runbook_client=runbook_client,
        )
        # Configure the module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build the compiled graph
        graph = create_incident_commander_graph()
        self._app = graph.compile()

        # In-memory store of completed runs (fallback when no DB)
        self._results: dict[str, IncidentCommanderState] = {}

    @enforced("incident_commander")
    async def run(
        self,
        incident_context: IncidentContext,
    ) -> IncidentCommanderState:
        """Run a full incident commander coordination workflow.

        Args:
            incident_context: Context describing the incident to respond to.

        Returns:
            The completed IncidentCommanderState with resolution details.
        """
        request_id = f"ic-{uuid4().hex[:12]}"

        logger.info(
            "incident_commander_started",
            request_id=request_id,
            alert_id=incident_context.alert_id,
            service=incident_context.service,
            severity=incident_context.severity.value,
        )

        initial_state = IncidentCommanderState(
            request_id=request_id,
            incident_context=incident_context,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                    },
                    "recursion_limit": 25,
                },
            )

            final_state = IncidentCommanderState.model_validate(final_state_dict)

            # Calculate total duration
            if final_state.session_start:
                final_state.session_duration_ms = int(
                    (datetime.now(UTC) - final_state.session_start).total_seconds() * 1000
                )

            logger.info(
                "incident_commander_completed",
                request_id=request_id,
                stage=final_state.stage,
                tasks=len(final_state.agent_tasks),
                decisions=len(final_state.decisions),
                escalation=final_state.escalation_status,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "incident_commander_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IncidentCommanderState(
                request_id=request_id,
                incident_context=incident_context,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> IncidentCommanderState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "stage": state.stage,
                "status": state.current_step,
                "tasks": len(state.agent_tasks),
                "decisions": len(state.decisions),
                "escalation": state.escalation_status,
                "confidence": state.confidence_score,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

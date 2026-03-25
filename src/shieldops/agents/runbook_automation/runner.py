"""RunbookAutomationRunner — entry point for executing runbook automation workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.runbook_automation.graph import create_runbook_automation_graph
from shieldops.agents.runbook_automation.models import RunbookAutomationState
from shieldops.agents.runbook_automation.nodes import set_toolkit
from shieldops.agents.runbook_automation.tools import RunbookAutomationToolkit

logger = structlog.get_logger()


class RunbookAutomationRunner:
    """Runner for the Runbook Automation Agent."""

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RunbookAutomationToolkit(
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_runbook_automation_graph()
        self._app = graph.compile()
        self._results: dict[str, RunbookAutomationState] = {}
        logger.info("runbook_automation_runner.initialized")

    async def execute(
        self,
        tenant_id: str,
        runbook_name: str,
        target_service: str,
        extra_params: dict[str, Any] | None = None,
    ) -> RunbookAutomationState:
        """Run a runbook automation workflow.

        Args:
            tenant_id: Tenant or operator identifier.
            runbook_name: Name of the runbook from RUNBOOK_LIBRARY.
            target_service: Target service/deployment for the runbook.
            extra_params: Additional parameters passed to execution.

        Returns:
            Final RunbookAutomationState with full execution trace.
        """
        request_id = f"rba-{uuid4().hex[:12]}"
        initial_state = RunbookAutomationState(
            request_id=request_id,
            tenant_id=tenant_id,
            stats={
                "runbook_name": runbook_name,
                "target_service": target_service,
                **(extra_params or {}),
            },
        )

        logger.info(
            "runbook_automation_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            runbook_name=runbook_name,
            target_service=target_service,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "runbook_automation",
                    }
                },
            )
            final_state = RunbookAutomationState.model_validate(final_state_dict)
            self._results[request_id] = final_state

            logger.info(
                "runbook_automation_runner.completed",
                request_id=request_id,
                duration_ms=final_state.session_duration_ms,
                succeeded=final_state.stats.get("succeeded"),
            )
            return final_state

        except Exception as e:
            logger.error(
                "runbook_automation_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = RunbookAutomationState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> RunbookAutomationState | None:
        """Retrieve a previous execution result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all execution results with summary info."""
        return [
            {
                "request_id": rid,
                "current_step": state.current_step,
                "session_duration_ms": state.session_duration_ms,
                "rollback_triggered": state.rollback_triggered,
                "succeeded": state.stats.get("succeeded"),
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

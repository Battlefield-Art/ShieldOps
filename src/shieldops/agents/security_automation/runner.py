"""Security Automation Agent runner — entry point for executing automated responses.

Takes risk alerts, constructs the LangGraph, runs it end-to-end,
and returns the completed automation state.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_automation.graph import (
    create_security_automation_graph,
)
from shieldops.agents.security_automation.models import (
    RiskAlert,
    SecurityAutomationState,
)
from shieldops.agents.security_automation.nodes import set_toolkit
from shieldops.agents.security_automation.tools import (
    SecurityAutomationToolkit,
)

logger = structlog.get_logger()


class SecurityAutomationRunner:
    """Runs security automation agent workflows.

    Usage:
        runner = SecurityAutomationRunner(risk_threshold=50.0)
        result = await runner.run(alerts, dry_run=True)
    """

    def __init__(
        self,
        risk_threshold: float = 50.0,
        playbook_registry: list[dict[str, Any]] | None = None,
        repository: Any = None,
    ) -> None:
        self._toolkit = SecurityAutomationToolkit(
            risk_threshold=risk_threshold,
            playbook_registry=playbook_registry,
            repository=repository,
        )
        # Configure the module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build the compiled graph
        graph = create_security_automation_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._runs: dict[str, SecurityAutomationState] = {}

    async def run(
        self,
        alerts: list[RiskAlert],
        dry_run: bool = True,
    ) -> SecurityAutomationState:
        """Run the security automation workflow for a set of alerts.

        Args:
            alerts: Risk-based alerts to process.
            dry_run: If True (default), simulate containment actions.

        Returns:
            The completed SecurityAutomationState.
        """
        request_id = f"sa-{uuid4().hex[:12]}"

        logger.info(
            "security_automation_started",
            request_id=request_id,
            alert_count=len(alerts),
            dry_run=dry_run,
        )

        initial_state = SecurityAutomationState(
            request_id=request_id,
            alerts=alerts,
            dry_run=dry_run,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "dry_run": dry_run,
                    },
                },
            )

            final_state = SecurityAutomationState.model_validate(final_state_dict)

            logger.info(
                "security_automation_completed",
                request_id=request_id,
                triaged=len(final_state.triaged_alerts),
                playbook=(
                    final_state.selected_playbook.playbook_id
                    if final_state.selected_playbook
                    else "none"
                ),
                validation_passed=final_state.validation_passed,
                steps=len(final_state.reasoning_chain),
            )

            self._runs[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "security_automation_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityAutomationState(
                request_id=request_id,
                alerts=alerts,
                dry_run=dry_run,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = error_state
            return error_state

    def get_run(self, request_id: str) -> SecurityAutomationState | None:
        """Retrieve a completed run by ID."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "alert_count": len(state.alerts),
                "triaged_count": len(state.triaged_alerts),
                "playbook": (
                    state.selected_playbook.playbook_id if state.selected_playbook else None
                ),
                "validation_passed": state.validation_passed,
                "dry_run": state.dry_run,
                "steps": len(state.reasoning_chain),
                "error": state.error,
            }
            for rid, state in self._runs.items()
        ]

    @property
    def toolkit(self) -> SecurityAutomationToolkit:
        """Access the toolkit for inspecting learning history."""
        return self._toolkit

"""Security Automation Hub Agent runner -- entry point for automation cycles.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed SAH state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_automation_hub.graph import (
    create_security_automation_hub_graph,
)
from shieldops.agents.security_automation_hub.models import (
    SecurityAutomationHubState,
)
from shieldops.agents.security_automation_hub.nodes import (
    set_toolkit,
)
from shieldops.agents.security_automation_hub.tools import (
    SecurityAutomationHubToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityAutomationHubRunner:
    """Runs security automation hub workflows.

    Usage:
        runner = SecurityAutomationHubRunner(
            trigger_source=source,
            playbook_engine=engine,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        trigger_source: Any | None = None,
        playbook_engine: Any | None = None,
        execution_engine: Any | None = None,
        validator: Any | None = None,
        learning_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityAutomationHubToolkit(
            trigger_source=trigger_source,
            playbook_engine=playbook_engine,
            execution_engine=execution_engine,
            validator=validator,
            learning_store=learning_store,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_security_automation_hub_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, SecurityAutomationHubState] = {}

    @enforced("security_automation_hub")
    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityAutomationHubState:
        """Run a full security automation hub cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed SecurityAutomationHubState.
        """
        request_id = f"sah-{uuid4().hex[:12]}"

        logger.info(
            "sah_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = SecurityAutomationHubState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = SecurityAutomationHubState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "sah_completed",
                request_id=request_id,
                triggers=final_state.trigger_count,
                automations=final_state.automation_count,
                succeeded=final_state.success_count,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "sah_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityAutomationHubState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> SecurityAutomationHubState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": st.tenant_id,
                "stage": st.stage,
                "status": st.current_step,
                "triggers": st.trigger_count,
                "automations": st.automation_count,
                "succeeded": st.success_count,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]

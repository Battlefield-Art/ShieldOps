"""Autonomous Ops Controller Agent runner -- entry point for ops cycles.

Takes fleet configuration, constructs the LangGraph,
runs end-to-end, and returns completed AOC state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_ops_controller.graph import (
    create_autonomous_ops_controller_graph,
)
from shieldops.agents.autonomous_ops_controller.models import (
    AutonomousOpsControllerState,
)
from shieldops.agents.autonomous_ops_controller.nodes import (
    set_toolkit,
)
from shieldops.agents.autonomous_ops_controller.tools import (
    AutonomousOpsControllerToolkit,
)

logger = structlog.get_logger()


class AutonomousOpsControllerRunner:
    """Runs autonomous ops controller workflows.

    Usage:
        runner = AutonomousOpsControllerRunner(
            fleet_manager=fleet,
            task_scheduler=scheduler,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        fleet_manager: Any | None = None,
        task_scheduler: Any | None = None,
        execution_monitor: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutonomousOpsControllerToolkit(
            fleet_manager=fleet_manager,
            task_scheduler=task_scheduler,
            execution_monitor=execution_monitor,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_autonomous_ops_controller_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, AutonomousOpsControllerState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AutonomousOpsControllerState:
        """Run a full autonomous ops control cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed AutonomousOpsControllerState.
        """
        request_id = f"aoc-{uuid4().hex[:12]}"

        logger.info(
            "aoc_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = AutonomousOpsControllerState(
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

            final_state = AutonomousOpsControllerState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "aoc_completed",
                request_id=request_id,
                fleet_health=final_state.fleet_health,
                plans=len(final_state.operation_plans),
                dispatched=final_state.tasks_dispatched,
                succeeded=final_state.tasks_succeeded,
                success_rate=final_state.success_rate,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "aoc_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AutonomousOpsControllerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> AutonomousOpsControllerState | None:
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
                "fleet_health": st.fleet_health,
                "plans": len(st.operation_plans),
                "dispatched": st.tasks_dispatched,
                "succeeded": st.tasks_succeeded,
                "success_rate": st.success_rate,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]

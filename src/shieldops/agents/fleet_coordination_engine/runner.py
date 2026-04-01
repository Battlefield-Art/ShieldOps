"""Fleet Coordination Engine Agent runner — entry point
for executing fleet coordination workflows.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.fleet_coordination_engine.graph import (
    create_fleet_coordination_engine_graph,
)
from shieldops.agents.fleet_coordination_engine.models import (
    FleetCoordinationEngineState,
)
from shieldops.agents.fleet_coordination_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.fleet_coordination_engine.tools import (
    FleetCoordinationEngineToolkit,
)

logger = structlog.get_logger()


class FleetCoordinationEngineRunner:
    """Runner for the Fleet Coordination Engine Agent."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        health_monitor: Any | None = None,
        task_queue: Any | None = None,
        dispatcher: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = FleetCoordinationEngineToolkit(
            agent_registry=agent_registry,
            health_monitor=health_monitor,
            task_queue=task_queue,
            dispatcher=dispatcher,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_fleet_coordination_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, FleetCoordinationEngineState] = {}
        logger.info("fce_runner.initialized")

    async def run(
        self,
        tenant_id: str,
        request_id: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> FleetCoordinationEngineState:
        """Run fleet coordination workflow.

        Args:
            tenant_id: Tenant identifier.
            request_id: Optional request ID.
            config: Optional configuration with scope
                and dispatch strategy.

        Returns:
            Final FleetCoordinationEngineState with all
            discovered agents, health, routing, dispatch,
            and progress data.
        """
        session_id = f"fce-{uuid4().hex[:12]}"
        rid = request_id or f"fce-{uuid4().hex[:8]}"
        initial_state = FleetCoordinationEngineState(
            request_id=rid,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "fce_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            request_id=rid,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": ("fleet_coordination_engine"),
                    },
                },
            )
            final_state = FleetCoordinationEngineState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "fce_runner.completed",
                session_id=session_id,
                total_agents=final_state.total_agents,
                healthy=final_state.healthy_agents,
                dispatched=final_state.tasks_dispatched,
                completed=final_state.tasks_completed,
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "fce_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = FleetCoordinationEngineState(
                request_id=rid,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> FleetCoordinationEngineState | None:
        """Retrieve a previous coordination result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all coordination results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "request_id": state.request_id,
                "total_agents": state.total_agents,
                "healthy_agents": state.healthy_agents,
                "tasks_dispatched": (state.tasks_dispatched),
                "tasks_completed": (state.tasks_completed),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

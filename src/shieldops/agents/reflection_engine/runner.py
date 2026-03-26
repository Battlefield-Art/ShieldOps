"""Reflection Engine Agent runner — entry point for executing reflection workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.reflection_engine.graph import (
    create_reflection_engine_graph,
)
from shieldops.agents.reflection_engine.models import (
    ReflectionEngineState,
)
from shieldops.agents.reflection_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.reflection_engine.tools import (
    ReflectionEngineToolkit,
)

logger = structlog.get_logger()


class ReflectionEngineRunner:
    """Runner for the Reflection Engine Agent."""

    def __init__(
        self,
        action_store: Any | None = None,
        agent_registry: Any | None = None,
        config_backend: Any | None = None,
        metrics_backend: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ReflectionEngineToolkit(
            action_store=action_store,
            agent_registry=agent_registry,
            config_backend=config_backend,
            metrics_backend=metrics_backend,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_reflection_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, ReflectionEngineState] = {}
        logger.info("reflection_engine_runner.initialized")

    async def reflect(
        self,
        agent_id: str,
        time_range_hours: int = 24,
        tenant_id: str = "",
    ) -> ReflectionEngineState:
        """Run reflection analysis for an agent.

        Args:
            agent_id: ID of the agent to reflect on.
                Use '*' for cross-agent reflection.
            time_range_hours: How far back to look.
            tenant_id: Optional tenant scoping.

        Returns:
            Final ReflectionEngineState with all findings.
        """
        session_id = f"refl-{uuid4().hex[:12]}"
        initial_state = ReflectionEngineState(
            agent_id=agent_id,
            time_range_hours=time_range_hours,
            tenant_id=tenant_id,
        )

        logger.info(
            "reflection_engine_runner.starting",
            session_id=session_id,
            agent_id=agent_id,
            time_range_hours=time_range_hours,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "reflection_engine",
                    }
                },
            )
            final_state = ReflectionEngineState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "reflection_engine_runner.completed",
                session_id=session_id,
                actions_reviewed=(final_state.total_actions_reviewed),
                effectiveness=(final_state.effectiveness_score),
                mistakes=(final_state.total_mistakes_found),
                improvements=(final_state.total_improvements),
                learnings_applied=(final_state.total_learnings_applied),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "reflection_engine_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = ReflectionEngineState(
                agent_id=agent_id,
                time_range_hours=time_range_hours,
                tenant_id=tenant_id,
                error=str(e),
                current_stage="failed",  # type: ignore[arg-type]
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> ReflectionEngineState | None:
        """Retrieve a stored reflection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all reflection run summaries."""
        return [
            {
                "session_id": sid,
                "agent_id": state.agent_id,
                "actions_reviewed": (state.total_actions_reviewed),
                "effectiveness": (state.effectiveness_score),
                "mistakes": state.total_mistakes_found,
                "improvements": state.total_improvements,
                "learnings_applied": (state.total_learnings_applied),
                "current_stage": state.current_stage,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

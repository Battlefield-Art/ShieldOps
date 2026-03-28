"""Purple Team Orchestrator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.purple_team_orchestrator.graph import (
    create_purple_team_orchestrator_graph,
)
from shieldops.agents.purple_team_orchestrator.models import (
    ExercisePlan,
    ExerciseType,
    PurpleTeamOrchestratorState,
)
from shieldops.agents.purple_team_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.purple_team_orchestrator.tools import (
    PurpleTeamOrchestratorToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class PurpleTeamOrchestratorRunner:
    """Runs purple team exercises.

    Usage::

        runner = PurpleTeamOrchestratorRunner()
        result = await runner.orchestrate(
            tenant_id="acme",
            exercise_type="simulation",
        )
    """

    def __init__(
        self,
        red_team_client: Any | None = None,
        blue_team_client: Any | None = None,
        siem_client: Any | None = None,
    ) -> None:
        self._toolkit = PurpleTeamOrchestratorToolkit(
            red_team_client=red_team_client,
            blue_team_client=blue_team_client,
            siem_client=siem_client,
        )
        set_toolkit(self._toolkit)

        graph = create_purple_team_orchestrator_graph()
        self._app = graph.compile()
        self._runs: dict[str, PurpleTeamOrchestratorState] = {}

    async def orchestrate(
        self,
        tenant_id: str,
        exercise_type: str = "simulation",
        context: dict[str, Any] | None = None,
    ) -> PurpleTeamOrchestratorState:
        """Run a purple team exercise.

        Args:
            tenant_id: Tenant identifier.
            exercise_type: Type of exercise.
            context: Optional overrides.

        Returns:
            Completed state.
        """
        request_id = f"purple-{uuid4().hex[:12]}"

        logger.info(
            "purple_team_started",
            request_id=request_id,
            tenant_id=tenant_id,
            exercise_type=exercise_type,
        )

        ex_type = ExerciseType(exercise_type)
        initial = PurpleTeamOrchestratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            plan=ExercisePlan(
                exercise_type=ex_type,
            ),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("purple_team.orchestrate") as span:
                span.set_attribute(
                    "purple_team.request_id",
                    request_id,
                )
                span.set_attribute(
                    "purple_team.tenant_id",
                    tenant_id,
                )

                final_dict = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = PurpleTeamOrchestratorState.model_validate(final_dict)

                span.set_attribute(
                    "purple_team.blue_score",
                    final.blue_team_score,
                )

            logger.info(
                "purple_team_completed",
                request_id=request_id,
                red_score=final.red_team_score,
                blue_score=final.blue_team_score,
                duration_ms=final.session_duration_ms,
            )

            self._runs[request_id] = final
            return final

        except Exception as e:
            logger.error(
                "purple_team_failed",
                request_id=request_id,
                error=str(e),
            )
            err = PurpleTeamOrchestratorState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = err
            return err

    def get_run(
        self,
        request_id: str,
    ) -> PurpleTeamOrchestratorState | None:
        """Retrieve a completed run."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all exercise runs."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "exercise": s.plan.name,
                "status": s.current_step,
                "red_score": s.red_team_score,
                "blue_score": s.blue_team_score,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]

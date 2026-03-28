"""Incident Simulator Agent runner — entry point for executing simulations.

Takes scenario parameters, constructs the LangGraph, runs it end-to-end,
and returns the completed incident simulator state.
"""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.incident_simulator.graph import (
    create_incident_simulator_graph,
)
from shieldops.agents.incident_simulator.models import (
    ExerciseMode,
    IncidentSimulatorState,
    ScenarioType,
)
from shieldops.agents.incident_simulator.nodes import (
    set_toolkit,
)
from shieldops.agents.incident_simulator.tools import (
    IncidentSimulatorToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class IncidentSimulatorRunner:
    """Runs incident simulation workflows.

    Usage:
        runner = IncidentSimulatorRunner()
        result = await runner.execute(
            tenant_id="tenant-1",
            scenario_type="ransomware",
            exercise_mode="tabletop",
        )
    """

    def __init__(
        self,
        exercise_db: Any = None,
    ) -> None:
        self._toolkit = IncidentSimulatorToolkit(
            exercise_db=exercise_db,
        )
        set_toolkit(self._toolkit)

        graph = create_incident_simulator_graph()
        self._app = graph.compile()

        self._simulations: dict[str, IncidentSimulatorState] = {}

    async def execute(
        self,
        tenant_id: str,
        scenario_type: str = "ransomware",
        exercise_mode: str = "tabletop",
    ) -> IncidentSimulatorState:
        """Run a full incident simulation.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            scenario_type: Type of scenario (ransomware, data_breach, etc.).
            exercise_mode: Exercise mode (tabletop, functional, etc.).

        Returns:
            The completed IncidentSimulatorState with scores and report.
        """
        logger.info(
            "incident_simulation_started",
            tenant_id=tenant_id,
            scenario_type=scenario_type,
            exercise_mode=exercise_mode,
        )

        initial_state = IncidentSimulatorState(
            tenant_id=tenant_id,
            scenario_type=ScenarioType(scenario_type),
            exercise_mode=ExerciseMode(exercise_mode),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("incident_simulator.run") as span:
                span.set_attribute("simulator.tenant_id", tenant_id)
                span.set_attribute(
                    "simulator.scenario_type",
                    scenario_type,
                )
                span.set_attribute(
                    "simulator.exercise_mode",
                    exercise_mode,
                )

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),  # type: ignore[arg-type]
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                            "scenario_type": scenario_type,
                        },
                    },
                )

                final_state = IncidentSimulatorState.model_validate(final_state_dict)

                span.set_attribute(
                    "simulator.duration_ms",
                    final_state.duration_ms,
                )
                span.set_attribute(
                    "simulator.readiness_score",
                    final_state.readiness_score,
                )

            sim_id = (
                final_state.exercise.id
                if final_state.exercise
                else final_state.request_id or "unknown"
            )

            logger.info(
                "incident_simulation_completed",
                simulation_id=sim_id,
                tenant_id=tenant_id,
                duration_ms=final_state.duration_ms,
                readiness_score=final_state.readiness_score,
                stage=final_state.stage,
            )

            self._simulations[sim_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "incident_simulation_failed",
                tenant_id=tenant_id,
                scenario_type=scenario_type,
                error=str(e),
            )
            error_state = IncidentSimulatorState(
                tenant_id=tenant_id,
                scenario_type=ScenarioType(scenario_type),
                exercise_mode=ExerciseMode(exercise_mode),
                error=str(e),
            )
            return error_state

    def get_simulation(self, simulation_id: str) -> IncidentSimulatorState | None:
        """Retrieve a completed simulation by ID."""
        return self._simulations.get(simulation_id)

    def list_simulations(self) -> list[dict[str, Any]]:
        """List all simulations with summary info."""
        return [
            {
                "simulation_id": sim_id,
                "name": (state.exercise.name if state.exercise else "unknown"),
                "scenario_type": state.scenario_type,
                "exercise_mode": state.exercise_mode,
                "readiness_score": state.readiness_score,
                "stage": state.stage,
                "duration_ms": state.duration_ms,
                "error": state.error,
            }
            for sim_id, state in self._simulations.items()
        ]

"""Security Awareness Agent runner — entry point for executing assessments.

Takes awareness parameters, constructs the LangGraph, runs it end-to-end,
and returns the completed security awareness state.
"""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.security_awareness.graph import (
    create_security_awareness_graph,
)
from shieldops.agents.security_awareness.models import (
    SecurityAwarenessState,
    SimulationType,
)
from shieldops.agents.security_awareness.nodes import (
    set_toolkit,
)
from shieldops.agents.security_awareness.tools import (
    SecurityAwarenessToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class SecurityAwarenessRunner:
    """Runs security awareness assessment workflows.

    Usage:
        runner = SecurityAwarenessRunner()
        result = await runner.execute(
            tenant_id="tenant-1",
            simulation_type="phishing_email",
        )
    """

    def __init__(
        self,
        awareness_db: Any = None,
    ) -> None:
        self._toolkit = SecurityAwarenessToolkit(
            awareness_db=awareness_db,
        )
        set_toolkit(self._toolkit)

        graph = create_security_awareness_graph()
        self._app = graph.compile()

        self._assessments: dict[str, SecurityAwarenessState] = {}

    async def execute(
        self,
        tenant_id: str,
        simulation_type: str = "phishing_email",
    ) -> SecurityAwarenessState:
        """Run a full security awareness assessment.

        Args:
            tenant_id: Tenant identifier.
            simulation_type: Type of simulation to run.

        Returns:
            Completed SecurityAwarenessState with scores.
        """
        logger.info(
            "security_awareness_started",
            tenant_id=tenant_id,
            simulation_type=simulation_type,
        )

        initial_state = SecurityAwarenessState(
            tenant_id=tenant_id,
            simulation_type=SimulationType(simulation_type),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span(
                "security_awareness.run",
            ) as span:
                span.set_attribute(
                    "awareness.tenant_id",
                    tenant_id,
                )
                span.set_attribute(
                    "awareness.simulation_type",
                    simulation_type,
                )

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),  # type: ignore[arg-type]
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                            "simulation_type": (simulation_type),
                        },
                    },
                )

                final_state = SecurityAwarenessState.model_validate(
                    final_state_dict,
                )

                span.set_attribute(
                    "awareness.duration_ms",
                    final_state.duration_ms,
                )
                span.set_attribute(
                    "awareness.overall_score",
                    final_state.overall_score,
                )

            assessment_id = final_state.request_id or tenant_id

            logger.info(
                "security_awareness_completed",
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                duration_ms=final_state.duration_ms,
                overall_score=final_state.overall_score,
                stage=final_state.stage,
            )

            self._assessments[assessment_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "security_awareness_failed",
                tenant_id=tenant_id,
                simulation_type=simulation_type,
                error=str(e),
            )
            error_state = SecurityAwarenessState(
                tenant_id=tenant_id,
                simulation_type=SimulationType(
                    simulation_type,
                ),
                error=str(e),
            )
            return error_state

    def get_assessment(
        self,
        assessment_id: str,
    ) -> SecurityAwarenessState | None:
        """Retrieve a completed assessment by ID."""
        return self._assessments.get(assessment_id)

    def list_assessments(self) -> list[dict[str, Any]]:
        """List all assessments with summary info."""
        return [
            {
                "assessment_id": aid,
                "tenant_id": state.tenant_id,
                "simulation_type": state.simulation_type,
                "overall_score": state.overall_score,
                "stage": state.stage,
                "duration_ms": state.duration_ms,
                "error": state.error,
            }
            for aid, state in self._assessments.items()
        ]

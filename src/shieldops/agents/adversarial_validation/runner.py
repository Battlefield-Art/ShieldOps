"""Adversarial Validation Agent runner — entry point for validation workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.adversarial_validation.graph import (
    create_adversarial_validation_graph,
)
from shieldops.agents.adversarial_validation.models import (
    AdversarialValidationState,
)
from shieldops.agents.adversarial_validation.nodes import set_toolkit
from shieldops.agents.adversarial_validation.tools import (
    AdversarialValidationToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AdversarialValidationRunner:
    """Runs closed-loop adversarial validation workflows.

    Usage::

        runner = AdversarialValidationRunner()
        result = await runner.validate(tenant_id="acme-corp")
    """

    def __init__(
        self,
        red_team_client: Any | None = None,
        blue_team_client: Any | None = None,
        defense_monitor: Any | None = None,
    ) -> None:
        self._toolkit = AdversarialValidationToolkit(
            red_team_client=red_team_client,
            blue_team_client=blue_team_client,
            defense_monitor=defense_monitor,
        )
        set_toolkit(self._toolkit)

        graph = create_adversarial_validation_graph()
        self._app = graph.compile()

        self._validations: dict[str, AdversarialValidationState] = {}

    async def validate(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> AdversarialValidationState:
        """Run a full adversarial validation cycle.

        Collects red-team findings that have blue-team fixes, re-runs
        the attacks, assesses defense effectiveness, and feeds pattern
        updates back into the data flywheel.

        Args:
            tenant_id: Tenant whose defenses to validate.
            context: Optional overrides (e.g. specific finding IDs).

        Returns:
            The completed ``AdversarialValidationState`` with results.
        """
        request_id = f"av-{uuid4().hex[:12]}"
        context = context or {}

        logger.info(
            "adversarial_validation_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = AdversarialValidationState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("adversarial_validation.validate") as span:
                span.set_attribute("adversarial_validation.request_id", request_id)
                span.set_attribute("adversarial_validation.tenant_id", tenant_id)

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final_state = AdversarialValidationState.model_validate(final_state_dict)

                span.set_attribute(
                    "adversarial_validation.overall_effectiveness",
                    final_state.overall_effectiveness,
                )
                span.set_attribute(
                    "adversarial_validation.regressions_found",
                    final_state.regressions_found,
                )

            logger.info(
                "adversarial_validation_completed",
                request_id=request_id,
                tenant_id=tenant_id,
                findings=len(final_state.red_team_findings),
                tests=len(final_state.validation_tests),
                effectiveness=final_state.overall_effectiveness,
                regressions=final_state.regressions_found,
                pattern_updates=len(final_state.pattern_updates),
                duration_ms=final_state.session_duration_ms,
            )

            self._validations[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "adversarial_validation_failed",
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            error_state = AdversarialValidationState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._validations[request_id] = error_state
            return error_state

    def get_validation(self, request_id: str) -> AdversarialValidationState | None:
        """Retrieve a completed validation by request ID."""
        return self._validations.get(request_id)

    def list_validations(self) -> list[dict[str, Any]]:
        """List all validation runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "status": state.current_step,
                "findings": len(state.red_team_findings),
                "tests": len(state.validation_tests),
                "effectiveness": state.overall_effectiveness,
                "regressions": state.regressions_found,
                "pattern_updates": len(state.pattern_updates),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._validations.items()
        ]

"""Config Validator Agent runner — entry point for executing validations.

Takes a tenant ID, constructs the LangGraph, runs it end-to-end,
and returns the completed validation state.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.config_validator.graph import create_config_validator_graph
from shieldops.agents.config_validator.models import ConfigValidatorState
from shieldops.agents.config_validator.nodes import set_toolkit
from shieldops.agents.config_validator.tools import ConfigValidatorToolkit
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class ConfigValidatorRunner:
    """Runs config validator agent workflows.

    Usage:
        runner = ConfigValidatorRunner()
        result = await runner.validate(tenant_id="tenant-123")
    """

    def __init__(self) -> None:
        self._toolkit = ConfigValidatorToolkit()
        set_toolkit(self._toolkit)

        graph = create_config_validator_graph()
        self._app = graph.compile()

        # In-memory store of completed validations
        self._validations: dict[str, ConfigValidatorState] = {}

    async def validate(self, tenant_id: str) -> ConfigValidatorState:
        """Run a full config validation for a tenant.

        Args:
            tenant_id: The tenant whose infrastructure configs to validate.

        Returns:
            The completed ConfigValidatorState with drifts, impacts, and report.
        """
        run_id = f"cv-{uuid4().hex[:12]}"

        logger.info(
            "config_validation_started",
            run_id=run_id,
            tenant_id=tenant_id,
        )

        initial_state = ConfigValidatorState(
            tenant_id=tenant_id,
            run_id=run_id,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("config_validator.run") as span:
                span.set_attribute("config_validator.run_id", run_id)
                span.set_attribute("config_validator.tenant_id", tenant_id)

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),  # type: ignore[arg-type]
                    config={
                        "metadata": {
                            "run_id": run_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final_state = ConfigValidatorState.model_validate(final_state_dict)

                span.set_attribute("config_validator.total_configs", final_state.total_configs)
                span.set_attribute("config_validator.drift_count", final_state.drift_count)
                span.set_attribute("config_validator.duration_ms", final_state.duration_ms)

            logger.info(
                "config_validation_completed",
                run_id=run_id,
                tenant_id=tenant_id,
                total_configs=final_state.total_configs,
                compliant=final_state.compliant_count,
                drifts=final_state.drift_count,
                remediations=len(final_state.remediations),
                duration_ms=final_state.duration_ms,
            )

            self._validations[run_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "config_validation_failed",
                run_id=run_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            error_state = ConfigValidatorState(
                tenant_id=tenant_id,
                run_id=run_id,
                error=str(e),
            )
            self._validations[run_id] = error_state
            return error_state

    def get_validation(self, run_id: str) -> ConfigValidatorState | None:
        """Retrieve a completed validation by run ID."""
        return self._validations.get(run_id)

    def list_validations(self) -> list[dict[str, Any]]:
        """List all validations with summary info."""
        return [
            {
                "run_id": rid,
                "tenant_id": state.tenant_id,
                "stage": state.stage,
                "total_configs": state.total_configs,
                "compliant_count": state.compliant_count,
                "drift_count": state.drift_count,
                "duration_ms": state.duration_ms,
                "error": state.error,
            }
            for rid, state in self._validations.items()
        ]

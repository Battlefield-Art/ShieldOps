"""Chaos Engineering Agent runner — entry point for executing experiments.

Takes experiment parameters, constructs the LangGraph, runs it end-to-end,
and returns the completed chaos engineering state.
"""

from typing import Any

import structlog

from shieldops.agents.chaos_engineering.graph import create_chaos_engineering_graph
from shieldops.agents.chaos_engineering.models import ChaosEngineeringState
from shieldops.agents.chaos_engineering.nodes import set_toolkit
from shieldops.agents.chaos_engineering.tools import ChaosEngineeringToolkit
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class ChaosEngineeringRunner:
    """Runs chaos engineering experiment workflows.

    Usage:
        runner = ChaosEngineeringRunner()
        result = await runner.run_experiment(
            tenant_id="tenant-1",
            experiment_name="pod_kill_single",
            target_service="payment-svc",
            target_namespace="production",
        )
    """

    def __init__(
        self,
        opa_client: Any = None,
        k8s_client: Any = None,
    ) -> None:
        self._toolkit = ChaosEngineeringToolkit(
            opa_client=opa_client,
            k8s_client=k8s_client,
        )
        set_toolkit(self._toolkit)

        graph = create_chaos_engineering_graph()
        self._app = graph.compile()

        self._experiments: dict[str, ChaosEngineeringState] = {}

    async def run_experiment(
        self,
        tenant_id: str,
        experiment_name: str,
        target_service: str,
        target_namespace: str = "default",
    ) -> ChaosEngineeringState:
        """Run a full chaos engineering experiment.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            experiment_name: Name or library key for the experiment.
            target_service: Kubernetes service to target.
            target_namespace: Kubernetes namespace of the target.

        Returns:
            The completed ChaosEngineeringState with analysis and report.
        """
        logger.info(
            "chaos_experiment_started",
            tenant_id=tenant_id,
            experiment_name=experiment_name,
            target=f"{target_namespace}/{target_service}",
        )

        initial_state = ChaosEngineeringState(
            tenant_id=tenant_id,
            experiment_name=experiment_name,
            target_service=target_service,
            target_namespace=target_namespace,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("chaos_engineering.run") as span:
                span.set_attribute("chaos.tenant_id", tenant_id)
                span.set_attribute("chaos.experiment_name", experiment_name)
                span.set_attribute("chaos.target_service", target_service)
                span.set_attribute("chaos.target_namespace", target_namespace)

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),  # type: ignore[arg-type]
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                            "experiment_name": experiment_name,
                        },
                    },
                )

                final_state = ChaosEngineeringState.model_validate(final_state_dict)

                span.set_attribute("chaos.duration_ms", final_state.duration_ms)
                span.set_attribute("chaos.resilience_score", final_state.resilience_score)
                span.set_attribute(
                    "chaos.hypothesis_validated",
                    final_state.hypothesis_validated or False,
                )

            exp_id = final_state.experiment.id if final_state.experiment else "unknown"

            logger.info(
                "chaos_experiment_completed",
                experiment_id=exp_id,
                tenant_id=tenant_id,
                duration_ms=final_state.duration_ms,
                resilience_score=final_state.resilience_score,
                hypothesis_validated=final_state.hypothesis_validated,
                status=final_state.experiment.status if final_state.experiment else "unknown",
            )

            self._experiments[exp_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "chaos_experiment_failed",
                tenant_id=tenant_id,
                experiment_name=experiment_name,
                error=str(e),
            )
            error_state = ChaosEngineeringState(
                tenant_id=tenant_id,
                experiment_name=experiment_name,
                target_service=target_service,
                target_namespace=target_namespace,
                error=str(e),
                current_stage="failed",
            )
            return error_state

    def get_experiment(self, experiment_id: str) -> ChaosEngineeringState | None:
        """Retrieve a completed experiment by ID."""
        return self._experiments.get(experiment_id)

    def list_experiments(self) -> list[dict[str, Any]]:
        """List all experiments with summary info."""
        return [
            {
                "experiment_id": exp_id,
                "name": state.experiment.name if state.experiment else state.experiment_name,
                "status": state.experiment.status if state.experiment else "unknown",
                "target": f"{state.target_namespace}/{state.target_service}",
                "resilience_score": state.resilience_score,
                "hypothesis_validated": state.hypothesis_validated,
                "duration_ms": state.duration_ms,
                "error": state.error,
            }
            for exp_id, state in self._experiments.items()
        ]

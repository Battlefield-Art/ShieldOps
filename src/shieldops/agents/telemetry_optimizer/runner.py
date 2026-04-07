"""Telemetry Optimizer Agent runner — entry point for executing optimizations.

Takes a namespace, constructs the LangGraph, runs it end-to-end,
and returns the completed optimizer state.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.telemetry_optimizer.graph import create_telemetry_optimizer_graph
from shieldops.agents.telemetry_optimizer.models import TelemetryOptimizerState
from shieldops.agents.telemetry_optimizer.nodes import set_toolkit
from shieldops.agents.telemetry_optimizer.tools import TelemetryOptimizerToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class TelemetryOptimizerRunner:
    """Runs telemetry optimizer agent workflows.

    Usage:
        runner = TelemetryOptimizerRunner(
            connector_router=router,
            metrics_backend=prometheus,
            cost_api=cost_service,
        )
        result = await runner.run("production")
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        metrics_backend: Any = None,
        cost_api: Any = None,
    ) -> None:
        self._toolkit = TelemetryOptimizerToolkit(
            connector_router=connector_router,
            metrics_backend=metrics_backend,
            cost_api=cost_api,
        )
        # Configure the module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build the compiled graph
        graph = create_telemetry_optimizer_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._runs: dict[str, TelemetryOptimizerState] = {}

    @enforced("telemetry_optimizer")
    async def run(
        self,
        namespace: str,
        budget_seconds: int = 300,
    ) -> TelemetryOptimizerState:
        """Run a full telemetry optimization pass for a namespace.

        Args:
            namespace: The Kubernetes namespace or service group to optimize.
            budget_seconds: Maximum time budget per experiment in seconds.

        Returns:
            The completed TelemetryOptimizerState with proposals and results.
        """
        request_id = f"topt-{uuid4().hex[:12]}"

        logger.info(
            "telemetry_optimization_started",
            request_id=request_id,
            namespace=namespace,
            budget_seconds=budget_seconds,
        )

        initial_state = TelemetryOptimizerState(
            request_id=request_id,
            target_namespace=namespace,
            budget_seconds=budget_seconds,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "namespace": namespace,
                    },
                },
            )

            final_state = TelemetryOptimizerState.model_validate(final_state_dict)

            logger.info(
                "telemetry_optimization_completed",
                request_id=request_id,
                namespace=namespace,
                waste_items=len(final_state.waste_items),
                proposals=len(final_state.proposals),
                accepted=sum(1 for e in final_state.experiments if e.accepted),
                total_savings_pct=final_state.total_savings_pct,
                confidence=final_state.confidence_score,
                steps=len(final_state.reasoning_chain),
            )

            self._runs[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "telemetry_optimization_failed",
                request_id=request_id,
                namespace=namespace,
                error=str(e),
            )
            error_state = TelemetryOptimizerState(
                request_id=request_id,
                target_namespace=namespace,
                budget_seconds=budget_seconds,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = error_state
            return error_state

    async def run_continuous(
        self,
        namespace: str,
        max_iterations: int = 10,
        budget_seconds: int = 300,
    ) -> list[TelemetryOptimizerState]:
        """Run optimization in a continuous loop for multiple iterations.

        Each iteration builds on the previous one's findings, targeting
        remaining waste that wasn't addressed.

        Args:
            namespace: The namespace to optimize.
            max_iterations: Maximum number of optimization passes.
            budget_seconds: Time budget per experiment per iteration.

        Returns:
            List of states from each iteration.
        """
        results: list[TelemetryOptimizerState] = []

        logger.info(
            "telemetry_continuous_optimization_started",
            namespace=namespace,
            max_iterations=max_iterations,
        )

        for iteration in range(max_iterations):
            logger.info(
                "telemetry_optimization_iteration",
                namespace=namespace,
                iteration=iteration + 1,
                max_iterations=max_iterations,
            )

            state = await self.run(namespace, budget_seconds=budget_seconds)
            results.append(state)

            # Stop if no waste found or error occurred
            if state.error or not state.waste_items:
                logger.info(
                    "telemetry_continuous_optimization_stopped_early",
                    namespace=namespace,
                    iteration=iteration + 1,
                    reason="no_waste" if not state.waste_items else "error",
                )
                break

            # Stop if confidence is high enough (most waste addressed)
            if state.confidence_score >= 0.9:
                logger.info(
                    "telemetry_continuous_optimization_converged",
                    namespace=namespace,
                    iteration=iteration + 1,
                    confidence=state.confidence_score,
                )
                break

        logger.info(
            "telemetry_continuous_optimization_completed",
            namespace=namespace,
            iterations=len(results),
            total_proposals=sum(len(r.proposals) for r in results),
            total_accepted=sum(sum(1 for e in r.experiments if e.accepted) for r in results),
        )

        return results

    def get_run(self, request_id: str) -> TelemetryOptimizerState | None:
        """Retrieve a completed optimization run by ID."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all optimization runs with summary info."""
        return [
            {
                "request_id": run_id,
                "namespace": state.target_namespace,
                "status": state.current_step,
                "waste_items": len(state.waste_items),
                "proposals": len(state.proposals),
                "accepted": sum(1 for e in state.experiments if e.accepted),
                "total_savings_pct": state.total_savings_pct,
                "confidence": state.confidence_score,
                "error": state.error,
            }
            for run_id, state in self._runs.items()
        ]

"""OTel Tail Sampling Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import OTelTailSamplingToolkit

logger = structlog.get_logger()


class OTelTailSamplingRunner:
    """Runs the OTel Tail Sampling agent workflow."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = OTelTailSamplingToolkit(
            k8s_client=k8s_client,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("otel_tail_sampling_runner.init")

    async def run(
        self,
        namespace: str = "default",
        budget_pct: float = 50.0,
    ) -> dict[str, Any]:
        """Execute the OTel Tail Sampling workflow.

        Args:
            namespace: Kubernetes namespace to analyze and configure.
            budget_pct: Target percentage of traces to retain (cost budget).
        """
        initial_state = {
            "request_id": "",
            "stage": "analyze",
            "target_namespace": namespace,
            "budget_pct": budget_pct,
            "trace_profiles": [],
            "policies": [],
            "simulations": [],
            "applied_policies": [],
            "cost_savings_pct": 0.0,
            "reasoning_chain": [],
            "error": "",
        }
        logger.info(
            "otel_tail_sampling_runner.run",
            namespace=namespace,
            budget_pct=budget_pct,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("otel_tail_sampling_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist tail sampling run results."""
        if self._repository:
            await self._repository.save_sampling_run(result)

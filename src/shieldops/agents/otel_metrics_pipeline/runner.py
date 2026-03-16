"""OTel Metrics Pipeline Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import OTelMetricsPipelineToolkit

logger = structlog.get_logger()


class OTelMetricsPipelineRunner:
    """Runs the OTel Metrics Pipeline agent workflow."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = OTelMetricsPipelineToolkit(
            k8s_client=k8s_client,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("otel_metrics_pipeline_runner.init")

    async def run(
        self,
        namespace: str = "default",
    ) -> dict[str, Any]:
        """Execute the OTel Metrics Pipeline workflow.

        Args:
            namespace: Kubernetes namespace to discover and configure metrics for.
        """
        initial_state = {  # type: ignore[var-annotated]
            "request_id": "",
            "stage": "discover",
            "target_namespace": namespace,
            "endpoints": [],
            "pipeline_config": None,
            "cardinality_reports": [],
            "golden_signals_coverage": {},
            "reasoning_chain": [],
            "error": "",
        }
        logger.info(
            "otel_metrics_pipeline_runner.run",
            namespace=namespace,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("otel_metrics_pipeline_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist metrics pipeline run results."""
        if self._repository:
            await self._repository.save_pipeline_run(result)

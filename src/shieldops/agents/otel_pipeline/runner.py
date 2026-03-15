"""OTel Pipeline Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import OTelPipelineToolkit

logger = structlog.get_logger()


class OTelPipelineRunner:
    """Runs the OTel Pipeline agent workflow."""

    def __init__(
        self,
        connector_router: Any | None = None,
        k8s_client: Any | None = None,
        kafka_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = OTelPipelineToolkit(
            connector_router=connector_router,
            k8s_client=k8s_client,
            kafka_client=kafka_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("otel_pipeline_runner.init")

    async def run(
        self,
        cluster_name: str,
        namespace: str = "default",
        exporter_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full OTel pipeline management workflow."""
        initial_state = {
            "request_id": "",
            "cluster_name": cluster_name,
            "namespace": namespace,
            "exporter_targets": exporter_targets or ["otlp"],
            "reasoning_chain": [],
        }
        logger.info(
            "otel_pipeline_runner.run",
            cluster=cluster_name,
            namespace=namespace,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("otel_pipeline_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist pipeline run results."""
        if self._repository:
            await self._repository.save_pipeline_run(result)

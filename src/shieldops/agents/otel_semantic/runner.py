"""OTel Semantic Conventions Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import OTelSemanticToolkit

logger = structlog.get_logger()


class OTelSemanticRunner:
    """Runs the OTel Semantic Conventions agent workflow."""

    def __init__(
        self,
        telemetry_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = OTelSemanticToolkit(
            telemetry_client=telemetry_client,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("otel_semantic_runner.init")

    @enforced("otel_semantic")
    async def run(
        self,
        services: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the OTel Semantic Conventions workflow."""
        if services is None:
            services = []

        initial_state = {
            "request_id": "",
            "target_services": services,
            "rules": [],
            "results": [],
            "overall_score": 0.0,
            "reasoning_chain": [],
            "error": "",
        }
        logger.info(
            "otel_semantic_runner.run",
            services=services,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("otel_semantic_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist semantic convention scan results."""
        if self._repository:
            await self._repository.save_semantic_scan(result)

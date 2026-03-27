"""Data Intelligence Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DataIntelligenceToolkit

logger = structlog.get_logger()


class DataIntelligenceRunner:
    """Runs the Data Intelligence agent workflow."""

    def __init__(
        self,
        catalog_client: Any | None = None,
        classifier: Any | None = None,
        lineage_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataIntelligenceToolkit(
            catalog_client=catalog_client,
            classifier=classifier,
            lineage_api=lineage_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("data_intel_runner.init")

    async def analyze(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute data intelligence workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "data_intel_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("data_intel_runner.analyze.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_analysis(result)

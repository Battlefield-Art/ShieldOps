"""Data Pipeline Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .tools import DataPipelineSecurityToolkit

logger = structlog.get_logger()


class DataPipelineSecurityRunner:
    """Runs the Data Pipeline Security agent workflow."""

    def __init__(
        self,
        vector_db_client: Any | None = None,
        model_registry: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataPipelineSecurityToolkit(
            vector_db_client=vector_db_client,
            model_registry=model_registry,
            threat_intel=threat_intel,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("data_pipeline_security_runner.init")

    async def scan(
        self,
        pipeline_id: str,
        data_sources: list[dict[str, Any]] | None = None,
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full data pipeline security scan workflow."""
        initial_state: dict[str, Any] = {
            "request_id": f"dps-{int(time.time())}",
            "pipeline_id": pipeline_id,
            "data_sources": data_sources or [],
            "scan_scope": scan_scope
            or [
                "rag_pipeline",
                "data_flows",
                "poisoning",
                "provenance",
            ],
            "session_start": time.time(),
            "reasoning_chain": [],
        }

        logger.info(
            "data_pipeline_security_runner.scan",
            pipeline_id=pipeline_id,
            source_count=len(data_sources or []),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("data_pipeline_security_runner.scan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist scan results."""
        if self._repository:
            await self._repository.save_scan_result(result)

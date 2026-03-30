"""Data Pipeline Protector Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .tools import DataPipelineProtectorToolkit

logger = structlog.get_logger()


class DataPipelineProtectorRunner:
    """Runs the Data Pipeline Protector agent workflow."""

    def __init__(
        self,
        pipeline_client: Any | None = None,
        schema_registry: Any | None = None,
        iam_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataPipelineProtectorToolkit(
            pipeline_client=pipeline_client,
            schema_registry=schema_registry,
            iam_client=iam_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("data_pipeline_protector_runner.init")

    async def protect(
        self,
        target_environment: str = "production",
        pipeline_ids: list[str] | None = None,
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full pipeline protection workflow."""
        initial_state: dict[str, Any] = {
            "request_id": f"dpp-{int(time.time())}",
            "target_environment": target_environment,
            "pipeline_ids": pipeline_ids or [],
            "scan_scope": scan_scope
            or [
                "discovery",
                "input_scan",
                "anomaly_detection",
                "schema_validation",
                "access_enforcement",
            ],
            "session_start": time.time(),
            "reasoning_chain": [],
        }

        logger.info(
            "data_pipeline_protector_runner.protect",
            environment=target_environment,
            pipeline_count=len(pipeline_ids or []),
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "data_pipeline_protector_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist protection results."""
        if self._repository:
            await self._repository.save_scan_result(result)

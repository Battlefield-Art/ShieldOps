"""Audit Trail Analyzer Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .nodes import set_toolkit
from .tools import AuditTrailAnalyzerToolkit

logger = structlog.get_logger()


class AuditTrailAnalyzerRunner:
    """Runs the Audit Trail Analyzer workflow."""

    def __init__(
        self,
        log_collector: Any | None = None,
        anomaly_engine: Any | None = None,
        correlation_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AuditTrailAnalyzerToolkit(
            log_collector=log_collector,
            anomaly_engine=anomaly_engine,
            correlation_engine=correlation_engine,
        )
        set_toolkit(self._toolkit)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("ata_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        sources: list[str] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute audit trail analysis."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        if sources:
            initial_state["sources"] = sources

        logger.info(
            "ata_runner.execute",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("ata_runner.execute.error")
            raise

    async def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a stored result by request ID."""
        if self._repository:
            return await self._repository.get(
                request_id,
            )
        return None

    async def list_results(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List recent analysis results."""
        if self._repository:
            return await self._repository.list(
                limit=limit,
            )
        return []

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        if self._repository:
            await self._repository.save(result)

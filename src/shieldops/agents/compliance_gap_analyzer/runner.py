"""Compliance Gap Analyzer Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ComplianceGapAnalyzerToolkit

logger = structlog.get_logger()


class ComplianceGapAnalyzerRunner:
    """Runs the Compliance Gap Analyzer agent workflow."""

    def __init__(
        self,
        compliance_db: Any | None = None,
        control_registry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceGapAnalyzerToolkit(
            compliance_db=compliance_db,
            control_registry=control_registry,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info(
            "compliance_gap_analyzer_runner.init",
        )

    async def analyze(
        self,
        tenant_id: str,
        frameworks: list[str] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Run compliance gap analysis."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "frameworks": frameworks
            or [
                "soc2",
                "hipaa",
                "nist_csf",
            ],
            "reasoning_chain": [],
        }

        logger.info(
            "compliance_gap_analyzer_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            frameworks=frameworks,
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
                "compliance_gap_analyzer_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist analysis results."""
        if self._repository:
            await self._repository.save(result)

"""Compliance Gap Analyzer Agent — Entry point."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import create_compliance_gap_analyzer_graph
from .tools import ComplianceGapAnalyzerToolkit

logger = structlog.get_logger()


class ComplianceGapAnalyzerRunner:
    """Runs the Compliance Gap Analyzer workflow."""

    def __init__(
        self,
        posture_backend: Any | None = None,
        regulatory_backend: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceGapAnalyzerToolkit(
            posture_backend=posture_backend,
            regulatory_backend=regulatory_backend,
        )
        self._repository = repository
        self._graph = create_compliance_gap_analyzer_graph(
            self._toolkit,
        )
        self._app = self._graph.compile()
        logger.info("cga_runner.init")

    @enforced("compliance_gap_analyzer")
    async def run(
        self,
        domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full gap analysis workflow."""
        if domains is None:
            domains = ["technology"]

        initial_state: dict[str, Any] = {
            "request_id": "",
            "tenant_id": "",
            "domains": domains,
            "reasoning_chain": [],
        }

        logger.info(
            "cga_runner.run",
            domains=domains,
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
                "cga_runner.run.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist gap analysis results."""
        if self._repository:
            await self._repository.save_gap_analysis(
                result,
            )

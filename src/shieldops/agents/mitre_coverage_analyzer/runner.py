"""MITRE Coverage Analyzer Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import MITRECoverageAnalyzerToolkit

logger = structlog.get_logger()


class MITRECoverageAnalyzerRunner:
    """Runs the MITRE Coverage Analyzer agent workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        edr_client: Any | None = None,
        mitre_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MITRECoverageAnalyzerToolkit(
            siem_client=siem_client,
            edr_client=edr_client,
            mitre_db=mitre_db,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info(
            "mitre_coverage_analyzer_runner.init",
        )

    async def analyze(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Run MITRE coverage analysis for a tenant."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "mitre_coverage_analyzer_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
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
                "mitre_coverage_analyzer_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist analysis results."""
        if self._repository:
            await self._repository.save(result)

"""Change Risk Analyzer Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .models import ChangeRequest
from .tools import ChangeRiskAnalyzerToolkit

logger = structlog.get_logger()


class ChangeRiskAnalyzerRunner:
    """Runs the Change Risk Analyzer agent workflow."""

    def __init__(
        self,
        git_client: Any | None = None,
        deployment_db: Any | None = None,
        incident_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ChangeRiskAnalyzerToolkit(
            git_client=git_client,
            deployment_db=deployment_db,
            incident_db=incident_db,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("change_risk_analyzer_runner.init")

    async def analyze(
        self,
        tenant_id: str = "",
        changes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute the full change risk analysis workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            changes: List of change request dicts to analyze. If None,
                     the agent will use sample data for demonstration.

        Returns:
            Final state dict with risk assessments, blast radius
            predictions, recommendations, and aggregate statistics.
        """
        # Normalize changes to ChangeRequest dicts
        change_requests: list[dict[str, Any]] = []
        if changes:
            for c in changes:
                if isinstance(c, ChangeRequest):
                    change_requests.append(c.model_dump())
                elif isinstance(c, dict):
                    change_requests.append(c)

        initial_state: dict[str, Any] = {
            "request_id": f"cra-{int(time.time())}",
            "tenant_id": tenant_id,
            "change_requests": change_requests,
            "session_start": time.time(),
            "reasoning_chain": [],
        }

        logger.info(
            "change_risk_analyzer_runner.analyze",
            tenant_id=tenant_id,
            change_count=len(change_requests),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("change_risk_analyzer_runner.analyze.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist change risk analysis results."""
        if self._repository:
            await self._repository.save_change_risk_analysis(result)

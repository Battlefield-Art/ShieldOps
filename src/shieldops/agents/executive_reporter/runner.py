"""Executive Reporter Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ExecutiveReporterToolkit

logger = structlog.get_logger()


class ExecutiveReporterRunner:
    """Runs the Executive Reporter agent workflow."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        metrics_store: Any | None = None,
        findings_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ExecutiveReporterToolkit(
            agent_registry=agent_registry,
            metrics_store=metrics_store,
            findings_db=findings_db,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info(
            "executive_reporter_runner.init",
        )

    async def generate(
        self,
        tenant_id: str,
        report_type: str = "weekly_posture",
        reporting_period: str = "",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Generate an executive report."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "report_type": report_type,
            "reporting_period": (reporting_period or "Current period"),
            "reasoning_chain": [],
        }

        logger.info(
            "executive_reporter_runner.generate",
            request_id=request_id,
            tenant_id=tenant_id,
            report_type=report_type,
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
                "executive_reporter_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist report results."""
        if self._repository:
            await self._repository.save(result)

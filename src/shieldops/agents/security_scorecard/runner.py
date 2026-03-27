"""Security Scorecard Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SecurityScorecardToolkit

logger = structlog.get_logger()


class SecurityScorecardRunner:
    """Runs the Security Scorecard agent workflow."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        metrics_store: Any | None = None,
        benchmark_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityScorecardToolkit(
            agent_registry=agent_registry,
            metrics_store=metrics_store,
            benchmark_db=benchmark_db,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("security_scorecard_runner.init")

    async def score(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Run security scoring for a tenant."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "security_scorecard_runner.score",
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
                "security_scorecard_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist scorecard results."""
        if self._repository:
            await self._repository.save(result)

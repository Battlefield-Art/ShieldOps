"""Performance Profiler Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import PerformanceProfilerToolkit

logger = structlog.get_logger()


class PerformanceProfilerRunner:
    """Runs the Performance Profiler agent workflow."""

    def __init__(
        self,
        apm_client: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PerformanceProfilerToolkit(
            apm_client=apm_client,
            metrics_store=metrics_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("performance_profiler_runner.init")

    async def profile(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full performance profiling workflow for a tenant."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "performance_profiler_runner.profile",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("performance_profiler_runner.profile.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist performance profiling results."""
        if self._repository:
            await self._repository.save_profile(result)

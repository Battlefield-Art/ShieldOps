"""Capacity Planner Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import CapacityPlannerToolkit

logger = structlog.get_logger()


class CapacityPlannerRunner:
    """Runs the Capacity Planner agent workflow."""

    def __init__(
        self,
        metrics_client: Any | None = None,
        cloud_provider: Any | None = None,
        cost_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CapacityPlannerToolkit(
            metrics_client=metrics_client,
            cloud_provider=cloud_provider,
            cost_api=cost_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("capacity_planner_runner.init")

    async def plan(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full capacity planning workflow for a tenant."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "capacity_planner_runner.plan",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("capacity_planner_runner.plan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist capacity planning results."""
        if self._repository:
            await self._repository.save_capacity_plan(result)

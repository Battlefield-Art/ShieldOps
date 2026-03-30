"""Cloud Migration Planner Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import CloudMigrationPlannerToolkit

logger = structlog.get_logger()


class CloudMigrationPlannerRunner:
    """Runs the Cloud Migration Planner workflow."""

    def __init__(
        self,
        discovery_api: Any | None = None,
        cloud_provider: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudMigrationPlannerToolkit(
            discovery_api=discovery_api,
            cloud_provider=cloud_provider,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("cmp_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute migration planning workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "cmp_runner.execute",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            self._results[request_id] = result
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "cmp_runner.execute.error",
            )
            raise

    def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a cached result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all cached results."""
        return [
            {
                "request_id": rid,
                "tenant_id": r.get(
                    "tenant_id",
                    "",
                ),
                "total_workloads": r.get(
                    "total_workloads",
                    0,
                ),
                "total_cost": r.get(
                    "total_estimated_cost",
                    0.0,
                ),
                "error": r.get("error", ""),
            }
            for rid, r in self._results.items()
        ]

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        if self._repository:
            await self._repository.save(result)

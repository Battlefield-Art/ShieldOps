"""Data Resilience Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DataResilienceToolkit

logger = structlog.get_logger()


class DataResilienceRunner:
    """Runs the Data Resilience agent workflow."""

    def __init__(
        self,
        storage_client: Any | None = None,
        cloud_provider: Any | None = None,
        backup_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataResilienceToolkit(
            storage_client=storage_client,
            cloud_provider=cloud_provider,
            backup_api=backup_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("data_resilience_runner.init")

    async def protect(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full data resilience workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "data_resilience_runner.protect",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("data_resilience_runner.protect.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist data resilience results."""
        if self._repository:
            await self._repository.save_resilience_report(result)

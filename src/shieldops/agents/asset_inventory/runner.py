"""Asset Inventory Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AssetInventoryToolkit

logger = structlog.get_logger()


class AssetInventoryRunner:
    """Runs the Asset Inventory agent workflow."""

    def __init__(
        self,
        cloud_client: Any | None = None,
        cmdb_client: Any | None = None,
        scanner_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AssetInventoryToolkit(
            cloud_client=cloud_client,
            cmdb_client=cmdb_client,
            scanner_client=scanner_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("asset_inventory_runner.init")

    async def manage(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full asset inventory workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "asset_inventory_runner.manage",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("asset_inventory_runner.manage.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist asset inventory results."""
        if self._repository:
            await self._repository.save_inventory_report(result)

"""Supply Chain Scanner Agent — Entry point and lifecycle management."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import SupplyChainScannerToolkit

logger = structlog.get_logger()


class SupplyChainScannerRunner:
    """Runs the Supply Chain Scanner workflow."""

    def __init__(
        self,
        model_registry_client: Any | None = None,
        rag_client: Any | None = None,
        template_store: Any | None = None,
        tool_registry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SupplyChainScannerToolkit(
            model_registry_client=(model_registry_client),
            rag_client=rag_client,
            template_store=template_store,
            tool_registry=tool_registry,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("supply_chain_scanner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full AI supply chain scan."""
        context = context or {}

        initial_state: dict[str, Any] = {
            "request_id": context.get(
                "request_id",
                str(uuid.uuid4())[:8],
            ),
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "supply_chain_scanner_runner.scan",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("supply_chain_scanner_runner.scan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist supply chain scan results."""
        if self._repository:
            await self._repository.save_scan(result)

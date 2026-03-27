"""IT Asset Intelligence Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ITAssetIntelligenceToolkit

logger = structlog.get_logger()


class ITAssetIntelligenceRunner:
    """Runs the IT Asset Intelligence agent workflow."""

    def __init__(
        self,
        cmdb_client: Any | None = None,
        threat_intel: Any | None = None,
        vuln_scanner: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ITAssetIntelligenceToolkit(
            cmdb_client=cmdb_client,
            threat_intel=threat_intel,
            vuln_scanner=vuln_scanner,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("it_asset_intel_runner.init")

    async def assess(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full IT asset intelligence workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "it_asset_intel_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("it_asset_intel_runner.assess.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_assessment(result)

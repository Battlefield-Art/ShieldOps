"""IOC Enrichment Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ioc_enrichment_engine.graph import (
    create_ioc_enrichment_engine_graph,
)
from shieldops.agents.ioc_enrichment_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.ioc_enrichment_engine.tools import (
    IOCEnrichmentEngineToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IOCEnrichmentEngineRunner:
    """Runs IOC enrichment workflows."""

    def __init__(
        self,
        client: Any = None,
    ) -> None:
        self._toolkit = IOCEnrichmentEngineToolkit(
            client=client,
        )
        set_toolkit(self._toolkit)
        graph = create_ioc_enrichment_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, Any] = {}

    @enforced("ioc_enrichment_engine")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """Run a full IOC enrichment workflow."""
        rid = f"iee-{uuid4().hex[:8]}"
        logger.info(
            "iee_run_started",
            request_id=rid,
            tenant_id=tenant_id,
        )
        result = await self._app.ainvoke(
            {
                "request_id": rid,
                "tenant_id": tenant_id,
            },
        )
        self._results[rid] = result
        return result

    def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[str]:
        """List all stored request IDs."""
        return list(self._results.keys())

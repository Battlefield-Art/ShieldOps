"""Browser Isolation Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import BrowserIsolationToolkit

logger = structlog.get_logger()


class BrowserIsolationRunner:
    """Runs the Browser Isolation agent workflow."""

    def __init__(
        self,
        isolation_client: Any | None = None,
        proxy_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BrowserIsolationToolkit(
            isolation_client=isolation_client,
            proxy_client=proxy_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("browser_isolation_runner.init")

    @enforced("browser_isolation")
    async def run(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the browser isolation workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        logger.info(
            "browser_isolation_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("browser_isolation_runner.error")
            raise

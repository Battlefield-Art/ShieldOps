"""Endpoint DLP Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import EndpointDLPToolkit

logger = structlog.get_logger()


class EndpointDLPRunner:
    """Runs the Endpoint DLP agent workflow."""

    def __init__(
        self,
        edr_client: Any | None = None,
        dlp_engine: Any | None = None,
        siem_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EndpointDLPToolkit(
            edr_client=edr_client,
            dlp_engine=dlp_engine,
            siem_client=siem_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("endpoint_dlp_runner.init")

    async def protect(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute endpoint DLP workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "endpoint_dlp_runner.protect",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("endpoint_dlp_runner.protect.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_dlp_result(result)

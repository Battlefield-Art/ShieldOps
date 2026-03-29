"""Endpoint Behavior Monitor Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import EndpointBehaviorMonitorToolkit

logger = structlog.get_logger()


class EndpointBehaviorMonitorRunner:
    """Runs the Endpoint Behavior Monitor agent workflow."""

    def __init__(
        self,
        edr_client: Any | None = None,
        siem_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EndpointBehaviorMonitorToolkit(
            edr_client=edr_client,
            siem_client=siem_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("endpoint_behavior_monitor_runner.init")

    async def run(
        self,
        tenant_id: str,
        endpoint_id: str = "",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the endpoint behavior monitor workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "endpoint_id": endpoint_id,
            "reasoning_chain": [],
        }
        logger.info(
            "endpoint_behavior_monitor_runner.run",
            request_id=request_id,
            endpoint_id=endpoint_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("endpoint_behavior_monitor_runner.error")
            raise

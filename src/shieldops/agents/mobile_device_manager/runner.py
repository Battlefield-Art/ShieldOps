"""Mobile Device Manager Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import MobileDeviceManagerToolkit

logger = structlog.get_logger()


class MobileDeviceManagerRunner:
    """Runs the Mobile Device Manager agent workflow."""

    def __init__(
        self,
        mdm_client: Any | None = None,
        directory_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MobileDeviceManagerToolkit(
            mdm_client=mdm_client,
            directory_client=directory_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("mobile_device_manager_runner.init")

    async def run(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the MDM workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        logger.info(
            "mobile_device_manager_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("mobile_device_manager_runner.error")
            raise

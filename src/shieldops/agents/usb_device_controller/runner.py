"""USB Device Controller Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import USBDeviceControllerToolkit

logger = structlog.get_logger()


class USBDeviceControllerRunner:
    """Runs the USB Device Controller agent workflow."""

    def __init__(
        self,
        endpoint_client: Any | None = None,
        dlp_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = USBDeviceControllerToolkit(
            endpoint_client=endpoint_client,
            dlp_client=dlp_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("usb_device_controller_runner.init")

    @enforced("usb_device_controller")
    async def run(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the USB device controller workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        logger.info(
            "usb_device_controller_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("usb_device_controller_runner.error")
            raise

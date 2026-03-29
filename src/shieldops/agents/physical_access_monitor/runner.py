"""Physical Access Monitor Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import PhysicalAccessMonitorToolkit

logger = structlog.get_logger()


class PhysicalAccessMonitorRunner:
    """Runs the Physical Access Monitor workflow."""

    def __init__(
        self,
        access_system: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PhysicalAccessMonitorToolkit(
            access_system=access_system,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("physical_access_monitor_runner.init")

    async def monitor(
        self,
        tenant_id: str,
        zones: list[str] | None = None,
        time_range_hours: int = 24,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute full physical access monitoring."""
        context = context or {}
        request_id = context.get(
            "request_id",
            str(uuid.uuid4()),
        )

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "zones": zones or [],
            "time_range_hours": time_range_hours,
            "reasoning_chain": [],
        }

        logger.info(
            "physical_access_monitor_runner.monitor",
            tenant_id=tenant_id,
            request_id=request_id,
        )
        try:
            start = time.time()
            result = await self._app.ainvoke(
                initial_state,
            )
            if isinstance(result, dict):
                result["session_duration_ms"] = round(
                    (time.time() - start) * 1000,
                    2,
                )
            if self._repository:
                await self._repository.save_scan(result)
            return result
        except Exception:
            logger.exception(
                "physical_access_monitor.error",
            )
            raise

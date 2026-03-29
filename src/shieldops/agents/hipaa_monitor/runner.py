"""HIPAA Monitor Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import create_hipaa_monitor_graph
from .tools import HIPAAMonitorToolkit

logger = structlog.get_logger()


class HIPAAMonitorRunner:
    """Runs the HIPAA Monitor agent workflow."""

    def __init__(
        self,
        hipaa_backend: Any | None = None,
        audit_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = HIPAAMonitorToolkit(
            hipaa_backend=hipaa_backend,
            audit_store=audit_store,
        )
        self._repository = repository
        self._graph = create_hipaa_monitor_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("hipaa_monitor_runner.init")

    async def run(
        self,
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Execute the HIPAA monitoring workflow."""
        initial_state: dict[str, Any] = {
            "request_id": "",
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "hipaa_monitor_runner.run",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("hipaa_monitor_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist HIPAA monitoring results."""
        if self._repository:
            await self._repository.save_hipaa_run(result)

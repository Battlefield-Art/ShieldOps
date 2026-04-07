"""GDPR Processor Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import create_gdpr_processor_graph
from .tools import GDPRProcessorToolkit

logger = structlog.get_logger()


class GDPRProcessorRunner:
    """Runs the GDPR Processor agent workflow."""

    def __init__(
        self,
        gdpr_backend: Any | None = None,
        consent_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = GDPRProcessorToolkit(
            gdpr_backend=gdpr_backend,
            consent_store=consent_store,
        )
        self._repository = repository
        self._graph = create_gdpr_processor_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("gdpr_processor_runner.init")

    @enforced("gdpr_processor")
    async def run(
        self,
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Execute the GDPR compliance workflow."""
        initial_state: dict[str, Any] = {
            "request_id": "",
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "gdpr_processor_runner.run",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("gdpr_processor_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist GDPR processing results."""
        if self._repository:
            await self._repository.save_gdpr_run(result)

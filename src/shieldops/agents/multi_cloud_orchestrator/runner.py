"""Multi Cloud Orchestrator — Runner."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import create_multi_cloud_orchestrator_graph
from .nodes import set_toolkit
from .tools import MultiCloudOrchestratorToolkit

logger = structlog.get_logger()


class MultiCloudOrchestratorRunner:
    """Runs the Multi Cloud Orchestrator workflow."""

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MultiCloudOrchestratorToolkit()
        set_toolkit(self._toolkit)
        self._graph = create_multi_cloud_orchestrator_graph()
        self._app = self._graph.compile()
        self._repository = repository
        self._results: list[dict[str, Any]] = []
        logger.info("mco_runner.init")

    @enforced("multi_cloud_orchestrator")
    async def execute(
        self,
        tenant_id: str = "default",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the multi-cloud orchestration workflow."""
        ctx = context or {}
        rid = ctx.get(
            "request_id",
            uuid.uuid4().hex[:8],
        )
        initial: dict[str, Any] = {
            "request_id": rid,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        logger.info(
            "mco_runner.execute",
            tenant_id=tenant_id,
            request_id=rid,
        )
        try:
            result = await self._app.ainvoke(initial)
            self._results.append(result)
            return result
        except Exception:
            logger.exception("mco_runner.execute.error")
            raise

    def get_result(
        self,
        index: int = -1,
    ) -> dict[str, Any] | None:
        """Get a stored result by index."""
        if not self._results:
            return None
        return self._results[index]

    def list_results(self) -> list[dict[str, Any]]:
        """List all stored results."""
        return list(self._results)

"""OTel Collector Manager Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .models import CollectorAction
from .tools import OTelCollectorManagerToolkit

logger = structlog.get_logger()


class OTelCollectorManagerRunner:
    """Runs the OTel Collector Manager agent workflow."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = OTelCollectorManagerToolkit(
            k8s_client=k8s_client,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("otel_collector_manager_runner.init")

    @enforced("otel_collector_manager")
    async def run(
        self,
        namespace: str = "default",
        action: str | CollectorAction = CollectorAction.DEPLOY,
    ) -> dict[str, Any]:
        """Execute the OTel Collector Manager workflow."""
        if isinstance(action, str):
            action = CollectorAction(action)

        initial_state = {  # type: ignore[var-annotated]
            "request_id": "",
            "action": action.value,
            "target_namespace": namespace,
            "reasoning_chain": [],
        }
        logger.info(
            "otel_collector_manager_runner.run",
            namespace=namespace,
            action=action.value,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("otel_collector_manager_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist collector manager run results."""
        if self._repository:
            await self._repository.save_collector_run(result)

"""OTel Deployment Orchestrator Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .models import DeployStage, RolloutStrategy
from .tools import OTelDeployerToolkit

logger = structlog.get_logger()


class OTelDeployerRunner:
    """Runs the OTel Deployment Orchestrator agent workflow."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = OTelDeployerToolkit(
            k8s_client=k8s_client,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("otel_deployer_runner.init")

    @enforced("otel_deployer")
    async def run(
        self,
        namespace: str = "default",
        strategy: str | RolloutStrategy = RolloutStrategy.ROLLING,
    ) -> dict[str, Any]:
        """Execute the OTel Deployment Orchestrator workflow."""
        if isinstance(strategy, str):
            strategy = RolloutStrategy(strategy)

        initial_state = {
            "request_id": "",
            "stage": DeployStage.PLAN.value,
            "targets": [],
            "plans": [],
            "results": [],
            "rollback_available": False,
            "confidence_score": 0.0,
            "reasoning_chain": [],
            "error": "",
            "strategy": strategy.value,
        }
        logger.info(
            "otel_deployer_runner.run",
            namespace=namespace,
            strategy=strategy.value,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("otel_deployer_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist deployer run results."""
        if self._repository:
            await self._repository.save_deployer_run(result)

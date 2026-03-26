"""Network Segmentation Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import NetworkSegmentationToolkit

logger = structlog.get_logger()


class NetworkSegmentationRunner:
    """Runs the Network Segmentation verification workflow."""

    def __init__(
        self,
        network_client: Any | None = None,
        firewall_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = NetworkSegmentationToolkit(
            network_client=network_client,
            firewall_client=firewall_client,
            policy_engine=policy_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("network_segmentation_runner.init")

    async def verify(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full network segmentation verification workflow."""
        context = context or {}
        environment = context.get("environment", "production")
        target_zones = context.get("target_zones", [])

        initial_state: dict[str, Any] = {
            "tenant_id": tenant_id,
            "environment": environment,
            "target_zones": target_zones,
            "reasoning_chain": [],
        }

        logger.info(
            "network_segmentation_runner.verify",
            tenant_id=tenant_id,
            environment=environment,
        )
        try:
            result = await self._app.ainvoke(
                initial_state  # type: ignore[arg-type]
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("network_segmentation_runner.verify.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist segmentation verification results."""
        if self._repository:
            await self._repository.save_segmentation_run(result)

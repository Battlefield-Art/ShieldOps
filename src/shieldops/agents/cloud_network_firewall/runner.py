"""Cloud Network Firewall Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .models import CloudPlatform
from .tools import CloudNetworkFirewallToolkit

logger = structlog.get_logger()


class CloudNetworkFirewallRunner:
    """Runs the Cloud Network Firewall agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudNetworkFirewallToolkit(
            cloud_clients=cloud_clients,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_network_firewall_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        platforms: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full firewall analysis workflow.

        Args:
            tenant_id: Tenant identifier for isolation.
            platforms: Cloud platforms to scan. Defaults
                to all supported platforms.

        Returns:
            Final agent state with security score,
            overpermissive rules, shadow rules,
            optimizations, and summary statistics.
        """
        if platforms is None:
            platforms = [p.value for p in CloudPlatform]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "platforms": platforms,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cloud_network_firewall_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            platforms=platforms,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("cloud_network_firewall_runner.analyze.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist firewall analysis results."""
        if self._repository:
            await self._repository.save_firewall_analysis(result)

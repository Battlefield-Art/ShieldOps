"""Shadow AI Discovery Agent — Entry point and lifecycle management."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import ShadowAIDiscoveryToolkit

logger = structlog.get_logger()


class ShadowAIDiscoveryRunner:
    """Runs the Shadow AI Discovery workflow."""

    def __init__(
        self,
        network_scanner: Any | None = None,
        asset_registry: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ShadowAIDiscoveryToolkit(
            network_scanner=network_scanner,
            asset_registry=asset_registry,
            policy_engine=policy_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("shadow_ai_discovery_runner.init")

    async def discover(
        self,
        tenant_id: str,
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full shadow AI discovery workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            scan_scope: Optional list of scan scopes. Supported values:
                "all", "cloud_llm", "local_llm", "mcp", "vector_db".
                Defaults to ["all"].

        Returns:
            Discovery results including assets, risk scores,
            and governance recommendations.
        """
        scan_scope = scan_scope or ["all"]
        request_id = f"sad-{uuid.uuid4().hex[:12]}"

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "scan_scope": scan_scope,
            "reasoning_chain": [],
        }

        logger.info(
            "shadow_ai_discovery_runner.discover",
            request_id=request_id,
            tenant_id=tenant_id,
            scan_scope=scan_scope,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "shadow_ai_discovery_runner.discover.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: Any) -> None:
        """Persist discovery results to repository."""
        try:
            if hasattr(self._repository, "save_discovery_result"):
                await self._repository.save_discovery_result(result)
        except Exception:
            logger.exception("shadow_ai_discovery_runner.persist.error")

"""Supply Chain Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import SupplyChainSecurityToolkit

logger = structlog.get_logger()


class SupplyChainSecurityRunner:
    """Runs the Supply Chain Security workflow."""

    def __init__(
        self,
        git_client: Any | None = None,
        registry_client: Any | None = None,
        ci_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SupplyChainSecurityToolkit(
            git_client=git_client,
            registry_client=registry_client,
            ci_client=ci_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("supply_chain_security_runner.init")

    async def scan(
        self,
        tenant_id: str,
        repositories: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full supply chain security scan workflow."""
        context = context or {}
        repos = repositories or context.get("repositories", [])

        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", str(uuid.uuid4())[:8]),
            "tenant_id": tenant_id,
            "repositories": repos,
            "reasoning_chain": [],
        }

        logger.info(
            "supply_chain_security_runner.scan",
            tenant_id=tenant_id,
            repo_count=len(repos),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("supply_chain_security_runner.scan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist supply chain scan results."""
        if self._repository:
            await self._repository.save_supply_chain_scan(result)

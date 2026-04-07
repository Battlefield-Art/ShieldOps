"""Agent Governance Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import AgentGovernanceToolkit

logger = structlog.get_logger()


class AgentGovernanceRunner:
    """Runs the Agent Governance agent workflow."""

    def __init__(
        self,
        registry_client: Any | None = None,
        policy_client: Any | None = None,
        notification_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AgentGovernanceToolkit(
            registry_client=registry_client,
            policy_client=policy_client,
            notification_client=notification_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("agent_governance_runner.init")

    @enforced("agent_governance")
    async def run(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full agent governance workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "agent_governance_runner.run",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("agent_governance_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_governance_report(result)

"""SOAR Workflow Orchestrator Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SOARWorkflowToolkit

logger = structlog.get_logger()


class SOARWorkflowRunner:
    """Runs the SOAR Workflow Orchestrator agent workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        edr_client: Any | None = None,
        firewall_client: Any | None = None,
        threat_intel_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SOARWorkflowToolkit(
            siem_client=siem_client,
            edr_client=edr_client,
            firewall_client=firewall_client,
            threat_intel_client=threat_intel_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("soar_workflow_runner.init")

    async def run(
        self,
        request_id: str = "",
        alert_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full SOAR workflow from alert intake through recovery."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "alert": alert_data or {},
            "reasoning_chain": [],
        }

        logger.info(
            "soar_workflow_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("soar_workflow_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist SOAR workflow results."""
        if self._repository:
            await self._repository.save_soar_workflow(result)

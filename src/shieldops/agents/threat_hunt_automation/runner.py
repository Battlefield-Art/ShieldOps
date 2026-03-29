"""Threat Hunt Automation Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_hunt_automation.graph import (
    create_threat_hunt_automation_graph,
)
from shieldops.agents.threat_hunt_automation.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_hunt_automation.tools import (
    ThreatHuntAutomationToolkit,
)

logger = structlog.get_logger()


class ThreatHuntAutomationRunner:
    """Runs threat hunt automation workflows."""

    def __init__(
        self,
        client: Any = None,
    ) -> None:
        self._toolkit = ThreatHuntAutomationToolkit(
            client=client,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_hunt_automation_graph()
        self._app = graph.compile()
        self._results: dict[str, Any] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """Run a full threat hunt workflow."""
        rid = f"tha-{uuid4().hex[:8]}"
        logger.info(
            "tha_run_started",
            request_id=rid,
            tenant_id=tenant_id,
        )
        result = await self._app.ainvoke(
            {
                "request_id": rid,
                "tenant_id": tenant_id,
            },
        )
        self._results[rid] = result
        return result

    def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[str]:
        """List all stored request IDs."""
        return list(self._results.keys())

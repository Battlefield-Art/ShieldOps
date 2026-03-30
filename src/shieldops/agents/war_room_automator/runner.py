"""War Room Automator — entry point and lifecycle."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from .graph import build_graph
from .nodes import set_toolkit
from .tools import WarRoomAutomatorToolkit

logger = structlog.get_logger()


class WarRoomAutomatorRunner:
    """Runner for the War Room Automator."""

    def __init__(
        self,
        chat_service: Any | None = None,
        oncall_service: Any | None = None,
    ) -> None:
        self._toolkit = WarRoomAutomatorToolkit(
            chat_service=chat_service,
            oncall_service=oncall_service,
        )
        set_toolkit(self._toolkit)
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("wra_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        incident_id: str = "",
        incident_title: str = "",
        incident_severity: str = "",
        incident_description: str = "",
        affected_services: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the war room workflow."""
        rid = f"wra-{uuid4().hex[:12]}"
        initial: dict[str, Any] = {
            "request_id": rid,
            "tenant_id": tenant_id,
            "incident_id": incident_id or rid,
            "incident_title": incident_title,
            "incident_severity": incident_severity,
            "incident_description": incident_description,
            "affected_services": affected_services or [],
            "reasoning_chain": [],
        }

        logger.info("wra_runner.execute", request_id=rid)
        try:
            result = await self._app.ainvoke(initial)
            self._results[rid] = result
            return result
        except Exception:
            logger.exception("wra_runner.error")
            raise

    async def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a previous result."""
        return self._results.get(request_id)

    async def list_results(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List recent results."""
        items = list(self._results.items())[-limit:]
        return [
            {
                "request_id": k,
                "current_step": v.get("current_step"),
                "error": v.get("error", ""),
            }
            for k, v in items
        ]

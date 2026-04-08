"""Incident Escalation Engine — entry point and lifecycle."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .nodes import set_toolkit
from .tools import IncidentEscalationEngineToolkit

logger = structlog.get_logger()


class IncidentEscalationEngineRunner:
    """Runner for the Incident Escalation Engine."""

    def __init__(
        self,
        notification_service: Any | None = None,
        oncall_service: Any | None = None,
    ) -> None:
        self._toolkit = IncidentEscalationEngineToolkit(
            notification_service=notification_service,
            oncall_service=oncall_service,
        )
        set_toolkit(self._toolkit)
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("iesc_runner.init")

    @enforced("incident_escalation_engine")
    async def execute(
        self,
        tenant_id: str = "default",
        incident_id: str = "",
        incident_title: str = "",
        incident_description: str = "",
        severity_raw: str = "",
        affected_services: list[str] | None = None,
        alert_count: int = 0,
    ) -> dict[str, Any]:
        """Execute the escalation workflow."""
        rid = f"iesc-{uuid4().hex[:12]}"
        initial: dict[str, Any] = {
            "request_id": rid,
            "tenant_id": tenant_id,
            "incident_id": incident_id or rid,
            "incident_title": incident_title,
            "incident_description": incident_description,
            "severity_raw": severity_raw,
            "affected_services": affected_services or [],
            "alert_count": alert_count,
            "reasoning_chain": [],
        }

        logger.info("iesc_runner.execute", request_id=rid)
        try:
            result = await self._app.ainvoke(initial)
            self._results[rid] = result
            return result
        except Exception:
            logger.exception("iesc_runner.error")
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

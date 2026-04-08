"""SLA Violation Detector — entry point and lifecycle."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .nodes import set_toolkit
from .tools import SLAViolationDetectorToolkit

logger = structlog.get_logger()


class SLAViolationDetectorRunner:
    """Runner for the SLA Violation Detector."""

    def __init__(
        self,
        metrics_service: Any | None = None,
        notification_service: Any | None = None,
    ) -> None:
        self._toolkit = SLAViolationDetectorToolkit(
            metrics_service=metrics_service,
            notification_service=notification_service,
        )
        set_toolkit(self._toolkit)
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("svd_runner.init")

    @enforced("sla_violation_detector")
    async def execute(
        self,
        tenant_id: str = "default",
        services: list[str] | None = None,
        time_window_hours: int = 24,
    ) -> dict[str, Any]:
        """Execute the SLA violation detection workflow."""
        rid = f"svd-{uuid4().hex[:12]}"
        initial: dict[str, Any] = {
            "request_id": rid,
            "tenant_id": tenant_id,
            "services": services or [],
            "time_window_hours": time_window_hours,
            "reasoning_chain": [],
        }

        logger.info("svd_runner.execute", request_id=rid)
        try:
            result = await self._app.ainvoke(initial)
            self._results[rid] = result
            return result
        except Exception:
            logger.exception("svd_runner.error")
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

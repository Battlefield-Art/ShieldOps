"""On-Call Optimizer — entry point and lifecycle."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .nodes import set_toolkit
from .tools import OnCallOptimizerToolkit

logger = structlog.get_logger()


class OnCallOptimizerRunner:
    """Runner for the On-Call Optimizer."""

    def __init__(
        self,
        schedule_service: Any | None = None,
        incident_service: Any | None = None,
    ) -> None:
        self._toolkit = OnCallOptimizerToolkit(
            schedule_service=schedule_service,
            incident_service=incident_service,
        )
        set_toolkit(self._toolkit)
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("oco_runner.init")

    @enforced("on_call_optimizer")
    async def execute(
        self,
        tenant_id: str = "default",
        team_id: str = "",
        team_members: list[str] | None = None,
        lookback_days: int = 90,
    ) -> dict[str, Any]:
        """Execute the on-call optimization workflow."""
        rid = f"oco-{uuid4().hex[:12]}"
        initial: dict[str, Any] = {
            "request_id": rid,
            "tenant_id": tenant_id,
            "team_id": team_id or rid,
            "team_members": team_members or [],
            "lookback_days": lookback_days,
            "reasoning_chain": [],
        }

        logger.info("oco_runner.execute", request_id=rid)
        try:
            result = await self._app.ainvoke(initial)
            self._results[rid] = result
            return result
        except Exception:
            logger.exception("oco_runner.error")
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

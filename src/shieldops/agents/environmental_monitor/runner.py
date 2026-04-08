"""Environmental Monitor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.environmental_monitor.graph import create_environmental_monitor_graph
from shieldops.agents.environmental_monitor.models import EnvironmentalMonitorState
from shieldops.agents.environmental_monitor.nodes import set_toolkit
from shieldops.agents.environmental_monitor.tools import EnvironmentalMonitorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class EnvironmentalMonitorRunner:
    """Runner for environmental_monitor."""

    def __init__(self) -> None:
        self._toolkit = EnvironmentalMonitorToolkit()
        set_toolkit(self._toolkit)
        graph = create_environmental_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, EnvironmentalMonitorState] = {}

    @enforced("environmental_monitor")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> EnvironmentalMonitorState:
        rid = f"env-{uuid4().hex[:12]}"
        initial = EnvironmentalMonitorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "environmental_monitor"}},
            )
            final = EnvironmentalMonitorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = EnvironmentalMonitorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> EnvironmentalMonitorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""Dark Web Monitor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.dark_web_monitor.graph import (
    create_dark_web_monitor_graph,
)
from shieldops.agents.dark_web_monitor.models import DarkWebMonitorState
from shieldops.agents.dark_web_monitor.nodes import set_toolkit
from shieldops.agents.dark_web_monitor.tools import DarkWebMonitorToolkit

logger = structlog.get_logger()


class DarkWebMonitorRunner:
    """Runner for dark_web_monitor."""

    def __init__(self) -> None:
        self._toolkit = DarkWebMonitorToolkit()
        set_toolkit(self._toolkit)
        graph = create_dark_web_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, DarkWebMonitorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> DarkWebMonitorState:
        rid = f"dar-{uuid4().hex[:12]}"
        initial = DarkWebMonitorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "dark_web_monitor"}},
            )
            final = DarkWebMonitorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DarkWebMonitorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> DarkWebMonitorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

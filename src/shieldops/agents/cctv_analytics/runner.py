"""CCTV Analytics Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cctv_analytics.graph import create_cctv_analytics_graph
from shieldops.agents.cctv_analytics.models import CCTVAnalyticsState
from shieldops.agents.cctv_analytics.nodes import set_toolkit
from shieldops.agents.cctv_analytics.tools import CCTVAnalyticsToolkit

logger = structlog.get_logger()


class CCTVAnalyticsRunner:
    """Runner for cctv_analytics."""

    def __init__(self) -> None:
        self._toolkit = CCTVAnalyticsToolkit()
        set_toolkit(self._toolkit)
        graph = create_cctv_analytics_graph()
        self._app = graph.compile()
        self._results: dict[str, CCTVAnalyticsState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> CCTVAnalyticsState:
        rid = f"cct-{uuid4().hex[:12]}"
        initial = CCTVAnalyticsState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "cctv_analytics"}},
            )
            final = CCTVAnalyticsState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = CCTVAnalyticsState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> CCTVAnalyticsState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

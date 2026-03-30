"""Behavioral Analytics Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.behavioral_analytics_engine.graph import (
    create_behavioral_analytics_engine_graph,
)
from shieldops.agents.behavioral_analytics_engine.models import (
    BehavioralAnalyticsEngineState,
)
from shieldops.agents.behavioral_analytics_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.behavioral_analytics_engine.tools import (
    BehavioralAnalyticsEngineToolkit,
)

logger = structlog.get_logger()


class BehavioralAnalyticsEngineRunner:
    """Runner for behavioral_analytics_engine."""

    def __init__(self) -> None:
        self._toolkit = BehavioralAnalyticsEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_behavioral_analytics_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, BehavioralAnalyticsEngineState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> BehavioralAnalyticsEngineState:
        rid = f"bae-{uuid4().hex[:12]}"
        initial = BehavioralAnalyticsEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "agent": "behavioral_analytics_engine",
                    }
                },
            )
            final = BehavioralAnalyticsEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = BehavioralAnalyticsEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> BehavioralAnalyticsEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

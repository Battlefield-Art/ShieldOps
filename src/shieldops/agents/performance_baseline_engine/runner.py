"""Performance Baseline Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.performance_baseline_engine.graph import (
    create_performance_baseline_engine_graph,
)
from shieldops.agents.performance_baseline_engine.models import (
    PerformanceBaselineEngineState,
)
from shieldops.agents.performance_baseline_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.performance_baseline_engine.tools import (
    PerformanceBaselineEngineToolkit,
)

logger = structlog.get_logger()


class PerformanceBaselineEngineRunner:
    """Runner for performance_baseline_engine."""

    def __init__(self) -> None:
        self._toolkit = PerformanceBaselineEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_performance_baseline_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, PerformanceBaselineEngineState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> PerformanceBaselineEngineState:
        rid = f"pbe-{uuid4().hex[:12]}"
        initial = PerformanceBaselineEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "agent": ("performance_baseline_engine"),
                    }
                },
            )
            final = PerformanceBaselineEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = PerformanceBaselineEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> PerformanceBaselineEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

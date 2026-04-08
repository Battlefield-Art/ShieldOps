"""Root Cause Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.root_cause_analyzer.graph import (
    create_root_cause_analyzer_graph,
)
from shieldops.agents.root_cause_analyzer.models import (
    RootCauseAnalyzerState,
)
from shieldops.agents.root_cause_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.root_cause_analyzer.tools import (
    RootCauseAnalyzerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class RootCauseAnalyzerRunner:
    """Runner for root_cause_analyzer."""

    def __init__(self) -> None:
        self._toolkit = RootCauseAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_root_cause_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, RootCauseAnalyzerState] = {}

    @enforced("root_cause_analyzer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> RootCauseAnalyzerState:
        rid = f"rca-{uuid4().hex[:12]}"
        initial = RootCauseAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "agent": "root_cause_analyzer",
                    }
                },
            )
            final = RootCauseAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = RootCauseAnalyzerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> RootCauseAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

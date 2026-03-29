"""Industrial Protocol Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.industrial_protocol_analyzer.graph import (
    create_industrial_protocol_analyzer_graph,
)
from shieldops.agents.industrial_protocol_analyzer.models import IndustrialProtocolAnalyzerState
from shieldops.agents.industrial_protocol_analyzer.nodes import set_toolkit
from shieldops.agents.industrial_protocol_analyzer.tools import IndustrialProtocolAnalyzerToolkit

logger = structlog.get_logger()


class IndustrialProtocolAnalyzerRunner:
    """Runner for industrial_protocol_analyzer."""

    def __init__(self) -> None:
        self._toolkit = IndustrialProtocolAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_industrial_protocol_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, IndustrialProtocolAnalyzerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> IndustrialProtocolAnalyzerState:
        rid = f"ind-{uuid4().hex[:12]}"
        initial = IndustrialProtocolAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "industrial_protocol_analyzer"}},
            )
            final = IndustrialProtocolAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = IndustrialProtocolAnalyzerState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> IndustrialProtocolAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

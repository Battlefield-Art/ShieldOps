"""Dependency Graph Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.dependency_graph_analyzer.graph import (
    create_dependency_graph_analyzer_graph,
)
from shieldops.agents.dependency_graph_analyzer.models import DependencyGraphAnalyzerState
from shieldops.agents.dependency_graph_analyzer.nodes import set_toolkit
from shieldops.agents.dependency_graph_analyzer.tools import DependencyGraphAnalyzerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class DependencyGraphAnalyzerRunner:
    """Runner for dependency_graph_analyzer."""

    def __init__(self) -> None:
        self._toolkit = DependencyGraphAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_dependency_graph_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, DependencyGraphAnalyzerState] = {}

    @enforced("dependency_graph_analyzer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> DependencyGraphAnalyzerState:
        rid = f"dep-{uuid4().hex[:12]}"
        initial = DependencyGraphAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "dependency_graph_analyzer"}},
            )
            final = DependencyGraphAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DependencyGraphAnalyzerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> DependencyGraphAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

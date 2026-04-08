"""SBOM Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.sbom_analyzer.graph import (
    create_sbom_analyzer_graph,
)
from shieldops.agents.sbom_analyzer.models import SbomAnalyzerState
from shieldops.agents.sbom_analyzer.nodes import set_toolkit
from shieldops.agents.sbom_analyzer.tools import SbomAnalyzerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SbomAnalyzerRunner:
    """Runner for sbom_analyzer."""

    def __init__(self) -> None:
        self._toolkit = SbomAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_sbom_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, SbomAnalyzerState] = {}

    @enforced("sbom_analyzer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SbomAnalyzerState:
        rid = f"sbo-{uuid4().hex[:12]}"
        initial = SbomAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "sbom_analyzer"}},
            )
            final = SbomAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SbomAnalyzerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SbomAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

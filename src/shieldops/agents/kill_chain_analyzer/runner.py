"""Kill Chain Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.kill_chain_analyzer.graph import (
    create_kill_chain_analyzer_graph,
)
from shieldops.agents.kill_chain_analyzer.models import KillChainAnalyzerState
from shieldops.agents.kill_chain_analyzer.nodes import set_toolkit
from shieldops.agents.kill_chain_analyzer.tools import KillChainAnalyzerToolkit

logger = structlog.get_logger()


class KillChainAnalyzerRunner:
    """Runner for kill_chain_analyzer."""

    def __init__(self) -> None:
        self._toolkit = KillChainAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_kill_chain_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, KillChainAnalyzerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> KillChainAnalyzerState:
        rid = f"kil-{uuid4().hex[:12]}"
        initial = KillChainAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "kill_chain_analyzer"}},
            )
            final = KillChainAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = KillChainAnalyzerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> KillChainAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""Attack Path Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_path_analyzer.graph import create_attack_path_analyzer_graph
from shieldops.agents.attack_path_analyzer.models import AttackPathAnalyzerState
from shieldops.agents.attack_path_analyzer.nodes import set_toolkit
from shieldops.agents.attack_path_analyzer.tools import AttackPathAnalyzerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AttackPathAnalyzerRunner:
    """Runner for attack_path_analyzer."""

    def __init__(self) -> None:
        self._toolkit = AttackPathAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_attack_path_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, AttackPathAnalyzerState] = {}

    @enforced("attack_path_analyzer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> AttackPathAnalyzerState:
        rid = f"apa-{uuid4().hex[:12]}"
        initial = AttackPathAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "attack_path_analyzer"}},
            )
            final = AttackPathAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = AttackPathAnalyzerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> AttackPathAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""SCADA Security Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.scada_security_analyzer.graph import create_scada_security_analyzer_graph
from shieldops.agents.scada_security_analyzer.models import SCADASecurityAnalyzerState
from shieldops.agents.scada_security_analyzer.nodes import set_toolkit
from shieldops.agents.scada_security_analyzer.tools import SCADASecurityAnalyzerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SCADASecurityAnalyzerRunner:
    """Runner for scada_security_analyzer."""

    def __init__(self) -> None:
        self._toolkit = SCADASecurityAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_scada_security_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, SCADASecurityAnalyzerState] = {}

    @enforced("scada_security_analyzer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SCADASecurityAnalyzerState:
        rid = f"sca-{uuid4().hex[:12]}"
        initial = SCADASecurityAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "scada_security_analyzer"}},
            )
            final = SCADASecurityAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SCADASecurityAnalyzerState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> SCADASecurityAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

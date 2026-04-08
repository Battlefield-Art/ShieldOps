"""AI Bias Scanner Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_bias_scanner.graph import create_ai_bias_scanner_graph
from shieldops.agents.ai_bias_scanner.models import AIBiasScannerState
from shieldops.agents.ai_bias_scanner.nodes import set_toolkit
from shieldops.agents.ai_bias_scanner.tools import AIBiasScannerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AIBiasScannerRunner:
    """Runner for ai_bias_scanner."""

    def __init__(self) -> None:
        self._toolkit = AIBiasScannerToolkit()
        set_toolkit(self._toolkit)
        graph = create_ai_bias_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, AIBiasScannerState] = {}

    @enforced("ai_bias_scanner")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> AIBiasScannerState:
        rid = f"ai_-{uuid4().hex[:12]}"
        initial = AIBiasScannerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "ai_bias_scanner"}},
            )
            final = AIBiasScannerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = AIBiasScannerState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> AIBiasScannerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

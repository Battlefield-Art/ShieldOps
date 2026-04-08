"""Model Explainability Auditor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.model_explainability_auditor.graph import (
    create_model_explainability_auditor_graph,
)
from shieldops.agents.model_explainability_auditor.models import ModelExplainabilityAuditorState
from shieldops.agents.model_explainability_auditor.nodes import set_toolkit
from shieldops.agents.model_explainability_auditor.tools import ModelExplainabilityAuditorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ModelExplainabilityAuditorRunner:
    """Runner for model_explainability_auditor."""

    def __init__(self) -> None:
        self._toolkit = ModelExplainabilityAuditorToolkit()
        set_toolkit(self._toolkit)
        graph = create_model_explainability_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, ModelExplainabilityAuditorState] = {}

    @enforced("model_explainability_auditor")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ModelExplainabilityAuditorState:
        rid = f"mod-{uuid4().hex[:12]}"
        initial = ModelExplainabilityAuditorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "model_explainability_auditor"}},
            )
            final = ModelExplainabilityAuditorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ModelExplainabilityAuditorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> ModelExplainabilityAuditorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

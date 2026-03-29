"""Runbook Knowledge Base Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.runbook_knowledge_base.graph import (
    create_runbook_knowledge_base_graph,
)
from shieldops.agents.runbook_knowledge_base.models import RunbookKnowledgeBaseState
from shieldops.agents.runbook_knowledge_base.nodes import set_toolkit
from shieldops.agents.runbook_knowledge_base.tools import RunbookKnowledgeBaseToolkit

logger = structlog.get_logger()


class RunbookKnowledgeBaseRunner:
    """Runner for runbook_knowledge_base."""

    def __init__(self) -> None:
        self._toolkit = RunbookKnowledgeBaseToolkit()
        set_toolkit(self._toolkit)
        graph = create_runbook_knowledge_base_graph()
        self._app = graph.compile()
        self._results: dict[str, RunbookKnowledgeBaseState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> RunbookKnowledgeBaseState:
        rid = f"run-{uuid4().hex[:12]}"
        initial = RunbookKnowledgeBaseState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "runbook_knowledge_base"}},
            )
            final = RunbookKnowledgeBaseState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = RunbookKnowledgeBaseState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> RunbookKnowledgeBaseState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

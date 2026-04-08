"""ISO 27001 Assessor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.iso27001_assessor.graph import create_iso27001_assessor_graph
from shieldops.agents.iso27001_assessor.models import ISO27001AssessorState
from shieldops.agents.iso27001_assessor.nodes import set_toolkit
from shieldops.agents.iso27001_assessor.tools import ISO27001AssessorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ISO27001AssessorRunner:
    """Runner for iso27001_assessor."""

    def __init__(self) -> None:
        self._toolkit = ISO27001AssessorToolkit()
        set_toolkit(self._toolkit)
        graph = create_iso27001_assessor_graph()
        self._app = graph.compile()
        self._results: dict[str, ISO27001AssessorState] = {}

    @enforced("iso27001_assessor")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ISO27001AssessorState:
        rid = f"iso-{uuid4().hex[:12]}"
        initial = ISO27001AssessorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "iso27001_assessor"}},
            )
            final = ISO27001AssessorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ISO27001AssessorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> ISO27001AssessorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

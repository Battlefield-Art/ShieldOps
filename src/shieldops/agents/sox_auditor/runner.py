"""SOX Auditor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.sox_auditor.graph import create_sox_auditor_graph
from shieldops.agents.sox_auditor.models import SOXAuditorState
from shieldops.agents.sox_auditor.nodes import set_toolkit
from shieldops.agents.sox_auditor.tools import SOXAuditorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SOXAuditorRunner:
    """Runner for sox_auditor."""

    def __init__(self) -> None:
        self._toolkit = SOXAuditorToolkit()
        set_toolkit(self._toolkit)
        graph = create_sox_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, SOXAuditorState] = {}

    @enforced("sox_auditor")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SOXAuditorState:
        rid = f"sox-{uuid4().hex[:12]}"
        initial = SOXAuditorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "sox_auditor"}},
            )
            final = SOXAuditorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SOXAuditorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> SOXAuditorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

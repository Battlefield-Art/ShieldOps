"""Communication Auditor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.communication_auditor.graph import create_communication_auditor_graph
from shieldops.agents.communication_auditor.models import CommunicationAuditorState
from shieldops.agents.communication_auditor.nodes import set_toolkit
from shieldops.agents.communication_auditor.tools import CommunicationAuditorToolkit

logger = structlog.get_logger()


class CommunicationAuditorRunner:
    """Runner for communication_auditor."""

    def __init__(self) -> None:
        self._toolkit = CommunicationAuditorToolkit()
        set_toolkit(self._toolkit)
        graph = create_communication_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, CommunicationAuditorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> CommunicationAuditorState:
        rid = f"com-{uuid4().hex[:12]}"
        initial = CommunicationAuditorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "communication_auditor"}},
            )
            final = CommunicationAuditorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = CommunicationAuditorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> CommunicationAuditorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

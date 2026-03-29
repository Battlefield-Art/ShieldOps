"""Defense In Depth Auditor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.defense_in_depth_auditor.graph import (
    create_defense_in_depth_auditor_graph,
)
from shieldops.agents.defense_in_depth_auditor.models import DefenseInDepthAuditorState
from shieldops.agents.defense_in_depth_auditor.nodes import set_toolkit
from shieldops.agents.defense_in_depth_auditor.tools import DefenseInDepthAuditorToolkit

logger = structlog.get_logger()


class DefenseInDepthAuditorRunner:
    """Runner for defense_in_depth_auditor."""

    def __init__(self) -> None:
        self._toolkit = DefenseInDepthAuditorToolkit()
        set_toolkit(self._toolkit)
        graph = create_defense_in_depth_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, DefenseInDepthAuditorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> DefenseInDepthAuditorState:
        rid = f"def-{uuid4().hex[:12]}"
        initial = DefenseInDepthAuditorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "defense_in_depth_auditor"}},
            )
            final = DefenseInDepthAuditorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DefenseInDepthAuditorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> DefenseInDepthAuditorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

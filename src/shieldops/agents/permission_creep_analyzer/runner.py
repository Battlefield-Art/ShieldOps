"""Permission Creep Analyzer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.permission_creep_analyzer.graph import (
    create_permission_creep_analyzer_graph,
)
from shieldops.agents.permission_creep_analyzer.models import PermissionCreepAnalyzerState
from shieldops.agents.permission_creep_analyzer.nodes import set_toolkit
from shieldops.agents.permission_creep_analyzer.tools import PermissionCreepAnalyzerToolkit

logger = structlog.get_logger()


class PermissionCreepAnalyzerRunner:
    """Runner for permission_creep_analyzer."""

    def __init__(self) -> None:
        self._toolkit = PermissionCreepAnalyzerToolkit()
        set_toolkit(self._toolkit)
        graph = create_permission_creep_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, PermissionCreepAnalyzerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> PermissionCreepAnalyzerState:
        rid = f"per-{uuid4().hex[:12]}"
        initial = PermissionCreepAnalyzerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "permission_creep_analyzer"}},
            )
            final = PermissionCreepAnalyzerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = PermissionCreepAnalyzerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> PermissionCreepAnalyzerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

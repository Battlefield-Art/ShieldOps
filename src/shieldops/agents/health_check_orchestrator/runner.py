"""Health Check Orchestrator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.health_check_orchestrator.graph import (
    create_health_check_orchestrator_graph,
)
from shieldops.agents.health_check_orchestrator.models import (
    HealthCheckOrchestratorState,
)
from shieldops.agents.health_check_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.health_check_orchestrator.tools import (
    HealthCheckOrchestratorToolkit,
)

logger = structlog.get_logger()


class HealthCheckOrchestratorRunner:
    """Runner for health_check_orchestrator."""

    def __init__(self) -> None:
        self._toolkit = HealthCheckOrchestratorToolkit()
        set_toolkit(self._toolkit)
        graph = create_health_check_orchestrator_graph()
        self._app = graph.compile()
        self._results: dict[str, HealthCheckOrchestratorState] = {}

    async def execute(self, tenant_id: str = "default") -> HealthCheckOrchestratorState:
        rid = f"hco-{uuid4().hex[:12]}"
        initial = HealthCheckOrchestratorState(request_id=rid, tenant_id=tenant_id)
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": ("health_check_orchestrator")}},
            )
            final = HealthCheckOrchestratorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = HealthCheckOrchestratorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> HealthCheckOrchestratorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

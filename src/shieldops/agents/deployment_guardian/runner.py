"""Deployment Guardian Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.deployment_guardian.graph import (
    create_deployment_guardian_graph,
)
from shieldops.agents.deployment_guardian.models import (
    DeploymentGuardianState,
)
from shieldops.agents.deployment_guardian.nodes import (
    set_toolkit,
)
from shieldops.agents.deployment_guardian.tools import (
    DeploymentGuardianToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class DeploymentGuardianRunner:
    """Runner for deployment_guardian."""

    def __init__(self) -> None:
        self._toolkit = DeploymentGuardianToolkit()
        set_toolkit(self._toolkit)
        graph = create_deployment_guardian_graph()
        self._app = graph.compile()
        self._results: dict[str, DeploymentGuardianState] = {}

    @enforced("deployment_guardian")
    async def execute(self, tenant_id: str = "default") -> DeploymentGuardianState:
        rid = f"dg-{uuid4().hex[:12]}"
        initial = DeploymentGuardianState(request_id=rid, tenant_id=tenant_id)
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": ("deployment_guardian")}},
            )
            final = DeploymentGuardianState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DeploymentGuardianState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> DeploymentGuardianState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

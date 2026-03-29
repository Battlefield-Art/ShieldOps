"""Building Management Security Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.building_management_security.graph import (
    create_building_management_security_graph,
)
from shieldops.agents.building_management_security.models import BuildingManagementSecurityState
from shieldops.agents.building_management_security.nodes import set_toolkit
from shieldops.agents.building_management_security.tools import BuildingManagementSecurityToolkit

logger = structlog.get_logger()


class BuildingManagementSecurityRunner:
    """Runner for building_management_security."""

    def __init__(self) -> None:
        self._toolkit = BuildingManagementSecurityToolkit()
        set_toolkit(self._toolkit)
        graph = create_building_management_security_graph()
        self._app = graph.compile()
        self._results: dict[str, BuildingManagementSecurityState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> BuildingManagementSecurityState:
        rid = f"bui-{uuid4().hex[:12]}"
        initial = BuildingManagementSecurityState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "building_management_security"}},
            )
            final = BuildingManagementSecurityState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = BuildingManagementSecurityState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> BuildingManagementSecurityState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""Service Dependency Mapper Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.service_dependency_mapper.graph import (
    create_service_dependency_mapper_graph,
)
from shieldops.agents.service_dependency_mapper.models import (
    ServiceDependencyMapperState,
)
from shieldops.agents.service_dependency_mapper.nodes import (
    set_toolkit,
)
from shieldops.agents.service_dependency_mapper.tools import (
    ServiceDependencyMapperToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ServiceDependencyMapperRunner:
    """Runner for service_dependency_mapper."""

    def __init__(self) -> None:
        self._toolkit = ServiceDependencyMapperToolkit()
        set_toolkit(self._toolkit)
        graph = create_service_dependency_mapper_graph()
        self._app = graph.compile()
        self._results: dict[str, ServiceDependencyMapperState] = {}

    @enforced("service_dependency_mapper")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ServiceDependencyMapperState:
        rid = f"sdm-{uuid4().hex[:12]}"
        initial = ServiceDependencyMapperState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "agent": "service_dependency_mapper",
                    }
                },
            )
            final = ServiceDependencyMapperState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ServiceDependencyMapperState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ServiceDependencyMapperState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

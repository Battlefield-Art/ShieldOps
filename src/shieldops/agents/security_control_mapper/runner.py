"""Security Control Mapper Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_control_mapper.graph import (
    create_security_control_mapper_graph,
)
from shieldops.agents.security_control_mapper.models import SecurityControlMapperState
from shieldops.agents.security_control_mapper.nodes import set_toolkit
from shieldops.agents.security_control_mapper.tools import SecurityControlMapperToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityControlMapperRunner:
    """Runner for security_control_mapper."""

    def __init__(self) -> None:
        self._toolkit = SecurityControlMapperToolkit()
        set_toolkit(self._toolkit)
        graph = create_security_control_mapper_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityControlMapperState] = {}

    @enforced("security_control_mapper")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SecurityControlMapperState:
        rid = f"sec-{uuid4().hex[:12]}"
        initial = SecurityControlMapperState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "security_control_mapper"}},
            )
            final = SecurityControlMapperState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SecurityControlMapperState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SecurityControlMapperState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""Just In Time Access Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.just_in_time_access.graph import (
    create_just_in_time_access_graph,
)
from shieldops.agents.just_in_time_access.models import JustInTimeAccessState
from shieldops.agents.just_in_time_access.nodes import set_toolkit
from shieldops.agents.just_in_time_access.tools import JustInTimeAccessToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class JustInTimeAccessRunner:
    """Runner for just_in_time_access."""

    def __init__(self) -> None:
        self._toolkit = JustInTimeAccessToolkit()
        set_toolkit(self._toolkit)
        graph = create_just_in_time_access_graph()
        self._app = graph.compile()
        self._results: dict[str, JustInTimeAccessState] = {}

    @enforced("just_in_time_access")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> JustInTimeAccessState:
        rid = f"jus-{uuid4().hex[:12]}"
        initial = JustInTimeAccessState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "just_in_time_access"}},
            )
            final = JustInTimeAccessState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = JustInTimeAccessState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> JustInTimeAccessState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

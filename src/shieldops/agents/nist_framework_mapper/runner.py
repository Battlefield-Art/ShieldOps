"""NIST Framework Mapper Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.nist_framework_mapper.graph import create_nist_framework_mapper_graph
from shieldops.agents.nist_framework_mapper.models import NISTFrameworkMapperState
from shieldops.agents.nist_framework_mapper.nodes import set_toolkit
from shieldops.agents.nist_framework_mapper.tools import NISTFrameworkMapperToolkit

logger = structlog.get_logger()


class NISTFrameworkMapperRunner:
    """Runner for nist_framework_mapper."""

    def __init__(self) -> None:
        self._toolkit = NISTFrameworkMapperToolkit()
        set_toolkit(self._toolkit)
        graph = create_nist_framework_mapper_graph()
        self._app = graph.compile()
        self._results: dict[str, NISTFrameworkMapperState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> NISTFrameworkMapperState:
        rid = f"nis-{uuid4().hex[:12]}"
        initial = NISTFrameworkMapperState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "nist_framework_mapper"}},
            )
            final = NISTFrameworkMapperState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = NISTFrameworkMapperState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> NISTFrameworkMapperState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

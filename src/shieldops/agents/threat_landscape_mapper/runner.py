"""Threat Landscape Mapper Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_landscape_mapper.graph import (
    create_threat_landscape_mapper_graph,
)
from shieldops.agents.threat_landscape_mapper.models import ThreatLandscapeMapperState
from shieldops.agents.threat_landscape_mapper.nodes import set_toolkit
from shieldops.agents.threat_landscape_mapper.tools import ThreatLandscapeMapperToolkit

logger = structlog.get_logger()


class ThreatLandscapeMapperRunner:
    """Runner for threat_landscape_mapper."""

    def __init__(self) -> None:
        self._toolkit = ThreatLandscapeMapperToolkit()
        set_toolkit(self._toolkit)
        graph = create_threat_landscape_mapper_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatLandscapeMapperState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ThreatLandscapeMapperState:
        rid = f"thr-{uuid4().hex[:12]}"
        initial = ThreatLandscapeMapperState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "threat_landscape_mapper"}},
            )
            final = ThreatLandscapeMapperState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ThreatLandscapeMapperState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ThreatLandscapeMapperState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

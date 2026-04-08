"""Incident Similarity Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_similarity_engine.graph import (
    create_incident_similarity_engine_graph,
)
from shieldops.agents.incident_similarity_engine.models import IncidentSimilarityEngineState
from shieldops.agents.incident_similarity_engine.nodes import set_toolkit
from shieldops.agents.incident_similarity_engine.tools import IncidentSimilarityEngineToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentSimilarityEngineRunner:
    """Runner for incident_similarity_engine."""

    def __init__(self) -> None:
        self._toolkit = IncidentSimilarityEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_incident_similarity_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentSimilarityEngineState] = {}

    @enforced("incident_similarity_engine")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> IncidentSimilarityEngineState:
        rid = f"inc-{uuid4().hex[:12]}"
        initial = IncidentSimilarityEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "incident_similarity_engine"}},
            )
            final = IncidentSimilarityEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = IncidentSimilarityEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> IncidentSimilarityEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

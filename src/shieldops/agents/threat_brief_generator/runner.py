"""Threat Brief Generator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_brief_generator.graph import (
    create_threat_brief_generator_graph,
)
from shieldops.agents.threat_brief_generator.models import ThreatBriefGeneratorState
from shieldops.agents.threat_brief_generator.nodes import set_toolkit
from shieldops.agents.threat_brief_generator.tools import ThreatBriefGeneratorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ThreatBriefGeneratorRunner:
    """Runner for threat_brief_generator."""

    def __init__(self) -> None:
        self._toolkit = ThreatBriefGeneratorToolkit()
        set_toolkit(self._toolkit)
        graph = create_threat_brief_generator_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatBriefGeneratorState] = {}

    @enforced("threat_brief_generator")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ThreatBriefGeneratorState:
        rid = f"thr-{uuid4().hex[:12]}"
        initial = ThreatBriefGeneratorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "threat_brief_generator"}},
            )
            final = ThreatBriefGeneratorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ThreatBriefGeneratorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ThreatBriefGeneratorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

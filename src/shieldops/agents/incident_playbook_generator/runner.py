"""Incident Playbook Generator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_playbook_generator.graph import (
    create_incident_playbook_generator_graph,
)
from shieldops.agents.incident_playbook_generator.models import (
    IncidentPlaybookGeneratorState,
)
from shieldops.agents.incident_playbook_generator.nodes import set_toolkit
from shieldops.agents.incident_playbook_generator.tools import (
    IncidentPlaybookGeneratorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentPlaybookGeneratorRunner:
    """Runner for incident_playbook_generator."""

    def __init__(self) -> None:
        self._toolkit = IncidentPlaybookGeneratorToolkit()
        set_toolkit(self._toolkit)
        graph = create_incident_playbook_generator_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentPlaybookGeneratorState] = {}

    @enforced("incident_playbook_generator")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> IncidentPlaybookGeneratorState:
        rid = f"ipg-{uuid4().hex[:12]}"
        initial = IncidentPlaybookGeneratorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "incident_playbook_generator"}},
            )
            final = IncidentPlaybookGeneratorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = IncidentPlaybookGeneratorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> IncidentPlaybookGeneratorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

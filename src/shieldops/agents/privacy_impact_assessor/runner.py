"""Privacy Impact Assessor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.privacy_impact_assessor.graph import (
    create_privacy_impact_assessor_graph,
)
from shieldops.agents.privacy_impact_assessor.models import PrivacyImpactAssessorState
from shieldops.agents.privacy_impact_assessor.nodes import set_toolkit
from shieldops.agents.privacy_impact_assessor.tools import PrivacyImpactAssessorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class PrivacyImpactAssessorRunner:
    """Runner for privacy_impact_assessor."""

    def __init__(self) -> None:
        self._toolkit = PrivacyImpactAssessorToolkit()
        set_toolkit(self._toolkit)
        graph = create_privacy_impact_assessor_graph()
        self._app = graph.compile()
        self._results: dict[str, PrivacyImpactAssessorState] = {}

    @enforced("privacy_impact_assessor")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> PrivacyImpactAssessorState:
        rid = f"pri-{uuid4().hex[:12]}"
        initial = PrivacyImpactAssessorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "privacy_impact_assessor"}},
            )
            final = PrivacyImpactAssessorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = PrivacyImpactAssessorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> PrivacyImpactAssessorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""Social Engineering Detector Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.social_engineering_detector.graph import (
    create_social_engineering_detector_graph,
)
from shieldops.agents.social_engineering_detector.models import SocialEngineeringDetectorState
from shieldops.agents.social_engineering_detector.nodes import set_toolkit
from shieldops.agents.social_engineering_detector.tools import SocialEngineeringDetectorToolkit

logger = structlog.get_logger()


class SocialEngineeringDetectorRunner:
    """Runner for social_engineering_detector."""

    def __init__(self) -> None:
        self._toolkit = SocialEngineeringDetectorToolkit()
        set_toolkit(self._toolkit)
        graph = create_social_engineering_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, SocialEngineeringDetectorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SocialEngineeringDetectorState:
        rid = f"soc-{uuid4().hex[:12]}"
        initial = SocialEngineeringDetectorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "social_engineering_detector"}},
            )
            final = SocialEngineeringDetectorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SocialEngineeringDetectorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> SocialEngineeringDetectorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

"""Orphan Account Detector Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.orphan_account_detector.graph import (
    create_orphan_account_detector_graph,
)
from shieldops.agents.orphan_account_detector.models import OrphanAccountDetectorState
from shieldops.agents.orphan_account_detector.nodes import set_toolkit
from shieldops.agents.orphan_account_detector.tools import OrphanAccountDetectorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class OrphanAccountDetectorRunner:
    """Runner for orphan_account_detector."""

    def __init__(self) -> None:
        self._toolkit = OrphanAccountDetectorToolkit()
        set_toolkit(self._toolkit)
        graph = create_orphan_account_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, OrphanAccountDetectorState] = {}

    @enforced("orphan_account_detector")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> OrphanAccountDetectorState:
        rid = f"orp-{uuid4().hex[:12]}"
        initial = OrphanAccountDetectorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "orphan_account_detector"}},
            )
            final = OrphanAccountDetectorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = OrphanAccountDetectorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> OrphanAccountDetectorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

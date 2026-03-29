"""Vendor Risk Assessor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.vendor_risk_assessor.graph import (
    create_vendor_risk_assessor_graph,
)
from shieldops.agents.vendor_risk_assessor.models import VendorRiskAssessorState
from shieldops.agents.vendor_risk_assessor.nodes import set_toolkit
from shieldops.agents.vendor_risk_assessor.tools import VendorRiskAssessorToolkit

logger = structlog.get_logger()


class VendorRiskAssessorRunner:
    """Runner for vendor_risk_assessor."""

    def __init__(self) -> None:
        self._toolkit = VendorRiskAssessorToolkit()
        set_toolkit(self._toolkit)
        graph = create_vendor_risk_assessor_graph()
        self._app = graph.compile()
        self._results: dict[str, VendorRiskAssessorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> VendorRiskAssessorState:
        rid = f"ven-{uuid4().hex[:12]}"
        initial = VendorRiskAssessorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "vendor_risk_assessor"}},
            )
            final = VendorRiskAssessorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = VendorRiskAssessorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> VendorRiskAssessorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

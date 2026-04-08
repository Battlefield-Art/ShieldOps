"""Compliance Automation Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_automation_engine.graph import (
    create_compliance_automation_engine_graph,
)
from shieldops.agents.compliance_automation_engine.models import (
    ComplianceAutomationEngineState,
)
from shieldops.agents.compliance_automation_engine.nodes import set_toolkit
from shieldops.agents.compliance_automation_engine.tools import (
    ComplianceAutomationEngineToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ComplianceAutomationEngineRunner:
    """Runner for compliance_automation_engine."""

    def __init__(self) -> None:
        self._toolkit = ComplianceAutomationEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_compliance_automation_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, ComplianceAutomationEngineState] = {}

    @enforced("compliance_automation_engine")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ComplianceAutomationEngineState:
        rid = f"cae-{uuid4().hex[:12]}"
        initial = ComplianceAutomationEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "compliance_automation_engine"}},
            )
            final = ComplianceAutomationEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ComplianceAutomationEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ComplianceAutomationEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

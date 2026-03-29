"""MFA Compliance Checker Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.mfa_compliance_checker.graph import (
    create_mfa_compliance_checker_graph,
)
from shieldops.agents.mfa_compliance_checker.models import MfaComplianceCheckerState
from shieldops.agents.mfa_compliance_checker.nodes import set_toolkit
from shieldops.agents.mfa_compliance_checker.tools import MfaComplianceCheckerToolkit

logger = structlog.get_logger()


class MfaComplianceCheckerRunner:
    """Runner for mfa_compliance_checker."""

    def __init__(self) -> None:
        self._toolkit = MfaComplianceCheckerToolkit()
        set_toolkit(self._toolkit)
        graph = create_mfa_compliance_checker_graph()
        self._app = graph.compile()
        self._results: dict[str, MfaComplianceCheckerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> MfaComplianceCheckerState:
        rid = f"mfa-{uuid4().hex[:12]}"
        initial = MfaComplianceCheckerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "mfa_compliance_checker"}},
            )
            final = MfaComplianceCheckerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = MfaComplianceCheckerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> MfaComplianceCheckerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

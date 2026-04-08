"""CI/CD Security Auditor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ci_cd_security_auditor.graph import (
    create_ci_cd_security_auditor_graph,
)
from shieldops.agents.ci_cd_security_auditor.models import CiCdSecurityAuditorState
from shieldops.agents.ci_cd_security_auditor.nodes import set_toolkit
from shieldops.agents.ci_cd_security_auditor.tools import CiCdSecurityAuditorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class CiCdSecurityAuditorRunner:
    """Runner for ci_cd_security_auditor."""

    def __init__(self) -> None:
        self._toolkit = CiCdSecurityAuditorToolkit()
        set_toolkit(self._toolkit)
        graph = create_ci_cd_security_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, CiCdSecurityAuditorState] = {}

    @enforced("ci_cd_security_auditor")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> CiCdSecurityAuditorState:
        rid = f"ci_-{uuid4().hex[:12]}"
        initial = CiCdSecurityAuditorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "ci_cd_security_auditor"}},
            )
            final = CiCdSecurityAuditorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = CiCdSecurityAuditorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> CiCdSecurityAuditorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

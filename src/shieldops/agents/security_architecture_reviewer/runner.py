"""Security Architecture Reviewer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_architecture_reviewer.graph import (
    create_security_architecture_reviewer_graph,
)
from shieldops.agents.security_architecture_reviewer.models import SecurityArchitectureReviewerState
from shieldops.agents.security_architecture_reviewer.nodes import set_toolkit
from shieldops.agents.security_architecture_reviewer.tools import (
    SecurityArchitectureReviewerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityArchitectureReviewerRunner:
    """Runner for security_architecture_reviewer."""

    def __init__(self) -> None:
        self._toolkit = SecurityArchitectureReviewerToolkit()
        set_toolkit(self._toolkit)
        graph = create_security_architecture_reviewer_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityArchitectureReviewerState] = {}

    @enforced("security_architecture_reviewer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SecurityArchitectureReviewerState:
        rid = f"sec-{uuid4().hex[:12]}"
        initial = SecurityArchitectureReviewerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "security_architecture_reviewer"}},
            )
            final = SecurityArchitectureReviewerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SecurityArchitectureReviewerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SecurityArchitectureReviewerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

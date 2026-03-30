"""Rate Limit Enforcer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.rate_limit_enforcer.graph import (
    create_rate_limit_enforcer_graph,
)
from shieldops.agents.rate_limit_enforcer.models import (
    RateLimitEnforcerState,
)
from shieldops.agents.rate_limit_enforcer.nodes import (
    set_toolkit,
)
from shieldops.agents.rate_limit_enforcer.tools import (
    RateLimitEnforcerToolkit,
)

logger = structlog.get_logger()


class RateLimitEnforcerRunner:
    """Runner for rate_limit_enforcer."""

    def __init__(self) -> None:
        self._toolkit = RateLimitEnforcerToolkit()
        set_toolkit(self._toolkit)
        graph = create_rate_limit_enforcer_graph()
        self._app = graph.compile()
        self._results: dict[str, RateLimitEnforcerState] = {}

    async def execute(self, tenant_id: str = "default") -> RateLimitEnforcerState:
        rid = f"rle-{uuid4().hex[:12]}"
        initial = RateLimitEnforcerState(request_id=rid, tenant_id=tenant_id)
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "rate_limit_enforcer"}},
            )
            final = RateLimitEnforcerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = RateLimitEnforcerState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> RateLimitEnforcerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

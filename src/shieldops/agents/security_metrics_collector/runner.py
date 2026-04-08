"""Security Metrics Collector Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_metrics_collector.graph import (
    create_security_metrics_collector_graph,
)
from shieldops.agents.security_metrics_collector.models import SecurityMetricsCollectorState
from shieldops.agents.security_metrics_collector.nodes import set_toolkit
from shieldops.agents.security_metrics_collector.tools import SecurityMetricsCollectorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityMetricsCollectorRunner:
    """Runner for security_metrics_collector."""

    def __init__(self) -> None:
        self._toolkit = SecurityMetricsCollectorToolkit()
        set_toolkit(self._toolkit)
        graph = create_security_metrics_collector_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityMetricsCollectorState] = {}

    @enforced("security_metrics_collector")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SecurityMetricsCollectorState:
        rid = f"smc-{uuid4().hex[:12]}"
        initial = SecurityMetricsCollectorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "security_metrics_collector"}},
            )
            final = SecurityMetricsCollectorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SecurityMetricsCollectorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SecurityMetricsCollectorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

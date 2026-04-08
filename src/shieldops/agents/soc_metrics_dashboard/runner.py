"""SOC Metrics Dashboard Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.soc_metrics_dashboard.graph import (
    create_soc_metrics_dashboard_graph,
)
from shieldops.agents.soc_metrics_dashboard.models import SocMetricsDashboardState
from shieldops.agents.soc_metrics_dashboard.nodes import set_toolkit
from shieldops.agents.soc_metrics_dashboard.tools import SocMetricsDashboardToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SocMetricsDashboardRunner:
    """Runner for soc_metrics_dashboard."""

    def __init__(self) -> None:
        self._toolkit = SocMetricsDashboardToolkit()
        set_toolkit(self._toolkit)
        graph = create_soc_metrics_dashboard_graph()
        self._app = graph.compile()
        self._results: dict[str, SocMetricsDashboardState] = {}

    @enforced("soc_metrics_dashboard")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SocMetricsDashboardState:
        rid = f"soc-{uuid4().hex[:12]}"
        initial = SocMetricsDashboardState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "soc_metrics_dashboard"}},
            )
            final = SocMetricsDashboardState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SocMetricsDashboardState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SocMetricsDashboardState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

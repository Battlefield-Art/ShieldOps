"""Threat Surface Minimizer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_surface_minimizer.graph import (
    create_threat_surface_minimizer_graph,
)
from shieldops.agents.threat_surface_minimizer.models import ThreatSurfaceMinimizerState
from shieldops.agents.threat_surface_minimizer.nodes import set_toolkit
from shieldops.agents.threat_surface_minimizer.tools import ThreatSurfaceMinimizerToolkit

logger = structlog.get_logger()


class ThreatSurfaceMinimizerRunner:
    """Runner for threat_surface_minimizer."""

    def __init__(self) -> None:
        self._toolkit = ThreatSurfaceMinimizerToolkit()
        set_toolkit(self._toolkit)
        graph = create_threat_surface_minimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatSurfaceMinimizerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ThreatSurfaceMinimizerState:
        rid = f"thr-{uuid4().hex[:12]}"
        initial = ThreatSurfaceMinimizerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "threat_surface_minimizer"}},
            )
            final = ThreatSurfaceMinimizerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ThreatSurfaceMinimizerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ThreatSurfaceMinimizerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

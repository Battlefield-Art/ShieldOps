"""Alert Enrichment Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.alert_enrichment_engine.graph import (
    create_alert_enrichment_engine_graph,
)
from shieldops.agents.alert_enrichment_engine.models import AlertEnrichmentEngineState
from shieldops.agents.alert_enrichment_engine.nodes import set_toolkit
from shieldops.agents.alert_enrichment_engine.tools import AlertEnrichmentEngineToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AlertEnrichmentEngineRunner:
    """Runner for alert_enrichment_engine."""

    def __init__(self) -> None:
        self._toolkit = AlertEnrichmentEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_alert_enrichment_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, AlertEnrichmentEngineState] = {}

    @enforced("alert_enrichment_engine")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> AlertEnrichmentEngineState:
        rid = f"ale-{uuid4().hex[:12]}"
        initial = AlertEnrichmentEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "alert_enrichment_engine"}},
            )
            final = AlertEnrichmentEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = AlertEnrichmentEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> AlertEnrichmentEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

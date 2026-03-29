"""Threat Correlation Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_correlation_engine.graph import (
    create_threat_correlation_engine_graph,
)
from shieldops.agents.threat_correlation_engine.models import ThreatCorrelationEngineState
from shieldops.agents.threat_correlation_engine.nodes import set_toolkit
from shieldops.agents.threat_correlation_engine.tools import ThreatCorrelationEngineToolkit

logger = structlog.get_logger()


class ThreatCorrelationEngineRunner:
    """Runner for threat_correlation_engine."""

    def __init__(self) -> None:
        self._toolkit = ThreatCorrelationEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_threat_correlation_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatCorrelationEngineState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ThreatCorrelationEngineState:
        rid = f"tce-{uuid4().hex[:12]}"
        initial = ThreatCorrelationEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "threat_correlation_engine"}},
            )
            final = ThreatCorrelationEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ThreatCorrelationEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ThreatCorrelationEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]

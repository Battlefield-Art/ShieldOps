"""SOC Metrics Analyzer runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.soc_metrics_analyzer.graph import (
    create_soc_metrics_analyzer_graph,
)
from shieldops.agents.soc_metrics_analyzer.models import (
    SOCMetricsAnalyzerState,
)
from shieldops.agents.soc_metrics_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.soc_metrics_analyzer.tools import (
    SOCMetricsAnalyzerToolkit,
)

logger = structlog.get_logger()


class SOCMetricsAnalyzerRunner:
    """Runner for the SOC Metrics Analyzer Agent."""

    def __init__(
        self,
        siem_client: Any | None = None,
        soar_client: Any | None = None,
        ticketing_client: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SOCMetricsAnalyzerToolkit(
            siem_client=siem_client,
            soar_client=soar_client,
            ticketing_client=ticketing_client,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_soc_metrics_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, SOCMetricsAnalyzerState] = {}
        logger.info("soc_metrics_analyzer_runner.init")

    async def analyze(
        self,
        time_range_days: int = 30,
        tenant_id: str = "",
        metric_sources: list[str] | None = None,
    ) -> SOCMetricsAnalyzerState:
        """Run a full SOC metrics analysis."""
        request_id = f"sma-{uuid4().hex[:12]}"
        initial = SOCMetricsAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            time_range_days=time_range_days,
            metric_sources=metric_sources or [],
        )
        logger.info(
            "sma_runner.analyze",
            request_id=request_id,
            days=time_range_days,
        )
        return await self._run(request_id, initial)

    async def quick_check(
        self,
        tenant_id: str = "",
    ) -> SOCMetricsAnalyzerState:
        """Run a 7-day quick health check."""
        return await self.analyze(
            time_range_days=7,
            tenant_id=tenant_id,
        )

    async def _run(
        self,
        request_id: str,
        initial: SOCMetricsAnalyzerState,
    ) -> SOCMetricsAnalyzerState:
        """Execute the graph workflow."""
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "soc_metrics_analyzer",
                    },
                },
            )
            final = SOCMetricsAnalyzerState.model_validate(
                result,
            )
            self._results[request_id] = final
            logger.info(
                "sma_runner.completed",
                request_id=request_id,
                score=final.overall_score,
                bottlenecks=len(final.bottlenecks),
                recommendations=len(
                    final.recommendations,
                ),
            )
            return final
        except Exception as exc:
            logger.error(
                "sma_runner.failed",
                request_id=request_id,
                error=str(exc),
            )
            error_state = SOCMetricsAnalyzerState(
                request_id=request_id,
                tenant_id=initial.tenant_id,
                error=str(exc),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SOCMetricsAnalyzerState | None:
        """Retrieve a previous analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "score": s.overall_score,
                "bottlenecks": len(s.bottlenecks),
                "recommendations": len(
                    s.recommendations,
                ),
                "step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

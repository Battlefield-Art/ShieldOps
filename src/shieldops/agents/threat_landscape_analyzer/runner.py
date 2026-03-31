"""Threat Landscape Analyzer Agent runner — entry point
for executing industry threat analysis and benchmarking."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_landscape_analyzer.graph import (
    create_threat_landscape_analyzer_graph,
)
from shieldops.agents.threat_landscape_analyzer.models import (
    IndustryVertical,
    ThreatLandscapeAnalyzerState,
)
from shieldops.agents.threat_landscape_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_landscape_analyzer.tools import (
    ThreatLandscapeAnalyzerToolkit,
)

logger = structlog.get_logger()


class ThreatLandscapeAnalyzerRunner:
    """Runner for the Threat Landscape Analyzer Agent."""

    def __init__(
        self,
        intel_aggregator: Any | None = None,
        trend_analyzer: Any | None = None,
        industry_mapper: Any | None = None,
        benchmark_engine: Any | None = None,
        brief_generator: Any | None = None,
        metrics_tracker: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatLandscapeAnalyzerToolkit(
            intel_aggregator=intel_aggregator,
            trend_analyzer=trend_analyzer,
            industry_mapper=industry_mapper,
            benchmark_engine=benchmark_engine,
            brief_generator=brief_generator,
            metrics_tracker=metrics_tracker,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_landscape_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatLandscapeAnalyzerState] = {}
        logger.info("tla_runner.initialized")

    async def analyze(
        self,
        industry: str = "technology",
        time_range: str = "30d",
        intel_sources: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> ThreatLandscapeAnalyzerState:
        """Run a threat landscape analysis."""
        request_id = f"tla-{uuid4().hex[:12]}"

        initial_state = ThreatLandscapeAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            industry=IndustryVertical(industry),
            time_range=time_range,
            intel_sources=intel_sources or [],
            scope=scope or {},
        )

        logger.info(
            "tla_runner.starting",
            request_id=request_id,
            industry=industry,
            time_range=time_range,
            sources=len(intel_sources or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("threat_landscape_analyzer"),
                    },
                },
            )
            final = ThreatLandscapeAnalyzerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "tla_runner.completed",
                request_id=request_id,
                total_threats=final.total_threats,
                critical=final.critical_threats,
                posture=final.posture_score,
                percentile=final.peer_percentile,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tla_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatLandscapeAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                industry=IndustryVertical(industry),
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> ThreatLandscapeAnalyzerState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "industry": s.industry.value,
                "total_threats": s.total_threats,
                "critical": s.critical_threats,
                "posture": s.posture_score,
                "percentile": s.peer_percentile,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

"""SIEM Rule Optimizer Agent runner — entry point for
executing detection rule optimization and tuning."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.siem_rule_optimizer.graph import (
    create_siem_rule_optimizer_graph,
)
from shieldops.agents.siem_rule_optimizer.models import (
    SIEMRuleOptimizerState,
)
from shieldops.agents.siem_rule_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.siem_rule_optimizer.tools import (
    SIEMRuleOptimizerToolkit,
)

logger = structlog.get_logger()


class SIEMRuleOptimizerRunner:
    """Runner for the SIEM Rule Optimizer Agent."""

    def __init__(
        self,
        siem_client: Any | None = None,
        rule_store: Any | None = None,
        performance_analyzer: Any | None = None,
        overlap_detector: Any | None = None,
        threshold_tuner: Any | None = None,
        metrics_recorder: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SIEMRuleOptimizerToolkit(
            siem_client=siem_client,
            rule_store=rule_store,
            performance_analyzer=performance_analyzer,
            overlap_detector=overlap_detector,
            threshold_tuner=threshold_tuner,
            metrics_recorder=metrics_recorder,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_siem_rule_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, SIEMRuleOptimizerState] = {}
        logger.info("sro_runner.initialized")

    async def optimize(
        self,
        siem_source: str,
        rule_filters: dict[str, Any] | None = None,
        optimization_config: dict[str, Any] | None = None,
        time_range: str = "30d",
        tenant_id: str = "",
    ) -> SIEMRuleOptimizerState:
        """Run SIEM rule optimization analysis."""
        request_id = f"sro-{uuid4().hex[:12]}"

        initial_state = SIEMRuleOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            siem_source=siem_source,
            rule_filters=rule_filters or {},
            optimization_config=optimization_config or {},
            time_range=time_range,
        )

        logger.info(
            "sro_runner.starting",
            request_id=request_id,
            siem=siem_source,
            time_range=time_range,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "siem_rule_optimizer",
                    },
                },
            )
            final = SIEMRuleOptimizerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sro_runner.completed",
                request_id=request_id,
                total_rules=final.total_rules,
                optimized=final.rules_optimized,
                fp_reduction=final.fp_reduction_pct,
                overlaps=final.overlap_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sro_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SIEMRuleOptimizerState(
                request_id=request_id,
                tenant_id=tenant_id,
                siem_source=siem_source,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SIEMRuleOptimizerState | None:
        """Retrieve a cached optimization result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all optimization results as summaries."""
        return [
            {
                "request_id": rid,
                "siem": s.siem_source,
                "total_rules": s.total_rules,
                "optimized": s.rules_optimized,
                "fp_reduction": s.fp_reduction_pct,
                "overlaps": s.overlap_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

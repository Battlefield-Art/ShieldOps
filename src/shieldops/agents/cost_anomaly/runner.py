"""Cost Anomaly Detector Agent runner — entry point for executing detection workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cost_anomaly.graph import create_cost_anomaly_graph
from shieldops.agents.cost_anomaly.models import CostAnomalyState
from shieldops.agents.cost_anomaly.nodes import set_toolkit
from shieldops.agents.cost_anomaly.tools import CostAnomalyToolkit

logger = structlog.get_logger()


class CostAnomalyRunner:
    """Runner for the Cost Anomaly Detector Agent."""

    def __init__(
        self,
        billing_client: Any | None = None,
        llm_cost_tracker: Any | None = None,
    ) -> None:
        self._toolkit = CostAnomalyToolkit(
            billing_client=billing_client,
            llm_cost_tracker=llm_cost_tracker,
        )
        set_toolkit(self._toolkit)
        graph = create_cost_anomaly_graph()
        self._app = graph.compile()
        self._results: dict[str, CostAnomalyState] = {}
        logger.info("cost_anomaly_runner.initialized")

    async def detect(self, tenant_id: str) -> dict[str, Any]:
        """Run cost anomaly detection workflow for a tenant.

        Returns a dictionary with the full analysis results including
        anomalies, waste classifications, LLM cost breakdown,
        recommendations, and aggregate stats.
        """
        run_id = f"ca-{uuid4().hex[:12]}"
        initial_state = CostAnomalyState(
            request_id=run_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "cost_anomaly_runner.starting",
            run_id=run_id,
            tenant_id=tenant_id,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": run_id,
                        "agent": "cost_anomaly",
                    }
                },
            )
            final_state = CostAnomalyState.model_validate(final_state_dict)
            self._results[run_id] = final_state

            logger.info(
                "cost_anomaly_runner.completed",
                run_id=run_id,
                anomalies=len(final_state.anomalies),
                waste_items=len(final_state.waste_classifications),
                recommendations=len(final_state.recommendations),
                total_monthly_waste=final_state.total_monthly_waste,
                duration_ms=final_state.session_duration_ms,
            )

            return {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "anomalies": [a.model_dump() for a in final_state.anomalies],
                "waste_classifications": [
                    w.model_dump() for w in final_state.waste_classifications
                ],
                "llm_cost_analysis": final_state.llm_cost_analysis,
                "recommendations": [r.model_dump() for r in final_state.recommendations],
                "total_monthly_waste": final_state.total_monthly_waste,
                "stats": final_state.stats,
                "reasoning_chain": [s.model_dump() for s in final_state.reasoning_chain],
                "duration_ms": final_state.session_duration_ms,
                "error": final_state.error,
            }

        except Exception as e:
            logger.error(
                "cost_anomaly_runner.failed",
                run_id=run_id,
                error=str(e),
            )
            error_state = CostAnomalyState(
                request_id=run_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[run_id] = error_state
            return {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "error": str(e),
                "anomalies": [],
                "waste_classifications": [],
                "llm_cost_analysis": {},
                "recommendations": [],
                "total_monthly_waste": 0.0,
                "stats": {},
                "reasoning_chain": [],
                "duration_ms": 0,
            }

    def get_result(self, run_id: str) -> CostAnomalyState | None:
        """Retrieve a cached result by run ID."""
        return self._results.get(run_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all cached detection results."""
        return [
            {
                "run_id": rid,
                "tenant_id": state.tenant_id,
                "anomalies": len(state.anomalies),
                "waste_items": len(state.waste_classifications),
                "recommendations": len(state.recommendations),
                "total_monthly_waste": state.total_monthly_waste,
                "current_step": state.current_step,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

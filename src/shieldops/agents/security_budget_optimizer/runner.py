"""Security Budget Optimizer runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_budget_optimizer.graph import (
    create_security_budget_optimizer_graph,
)
from shieldops.agents.security_budget_optimizer.models import (
    SecurityBudgetOptimizerState,
)
from shieldops.agents.security_budget_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.security_budget_optimizer.tools import (
    SecurityBudgetOptimizerToolkit,
)

logger = structlog.get_logger()


class SecurityBudgetOptimizerRunner:
    """Runner for the Security Budget Optimizer Agent."""

    def __init__(
        self,
        asset_inventory: Any | None = None,
        cost_tracker: Any | None = None,
        metrics_store: Any | None = None,
        contract_manager: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityBudgetOptimizerToolkit(
            asset_inventory=asset_inventory,
            cost_tracker=cost_tracker,
            metrics_store=metrics_store,
            contract_manager=contract_manager,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_budget_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityBudgetOptimizerState] = {}
        logger.info("sbo_runner.initialized")

    async def analyze(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> SecurityBudgetOptimizerState:
        """Run security budget optimization workflow."""
        sid = f"sbo-{uuid4().hex[:12]}"
        initial = SecurityBudgetOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "sbo_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_budget_optimizer",
                    },
                },
            )
            final = SecurityBudgetOptimizerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "sbo_runner.completed",
                session_id=sid,
                tools=len(final.tools_inventory),
                spend=final.total_spend,
                overlaps=len(final.overlap_analyses),
                allocations=len(final.budget_allocations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sbo_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecurityBudgetOptimizerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_config=scan_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> SecurityBudgetOptimizerState | None:
        """Retrieve a previous analysis result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_tools": len(s.tools_inventory),
                "total_spend": s.total_spend,
                "avg_roi": s.avg_roi,
                "overlaps": len(s.overlap_analyses),
                "allocations": len(s.budget_allocations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

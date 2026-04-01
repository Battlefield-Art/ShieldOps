"""Unified Risk Dashboard Agent runner -- entry point.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed URD state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.unified_risk_dashboard.graph import (
    create_unified_risk_dashboard_graph,
)
from shieldops.agents.unified_risk_dashboard.models import (
    UnifiedRiskDashboardState,
)
from shieldops.agents.unified_risk_dashboard.nodes import (
    set_toolkit,
)
from shieldops.agents.unified_risk_dashboard.tools import (
    UnifiedRiskDashboardToolkit,
)

logger = structlog.get_logger()


class UnifiedRiskDashboardRunner:
    """Runs unified risk dashboard workflows.

    Usage:
        runner = UnifiedRiskDashboardRunner(
            signal_collector=collector,
            posture_calculator=calculator,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        signal_collector: Any | None = None,
        score_normalizer: Any | None = None,
        risk_aggregator: Any | None = None,
        posture_calculator: Any | None = None,
        action_prioritizer: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = UnifiedRiskDashboardToolkit(
            signal_collector=signal_collector,
            score_normalizer=score_normalizer,
            risk_aggregator=risk_aggregator,
            posture_calculator=posture_calculator,
            action_prioritizer=action_prioritizer,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_unified_risk_dashboard_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, UnifiedRiskDashboardState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> UnifiedRiskDashboardState:
        """Run a full unified risk dashboard cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed UnifiedRiskDashboardState.
        """
        request_id = f"urd-{uuid4().hex[:12]}"

        logger.info(
            "urd_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = UnifiedRiskDashboardState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = UnifiedRiskDashboardState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "urd_completed",
                request_id=request_id,
                signals=final_state.signal_count,
                domains=final_state.domain_count,
                actions=final_state.action_count,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "urd_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = UnifiedRiskDashboardState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> UnifiedRiskDashboardState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": st.tenant_id,
                "stage": st.stage,
                "status": st.current_step,
                "signals": st.signal_count,
                "domains": st.domain_count,
                "actions": st.action_count,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]

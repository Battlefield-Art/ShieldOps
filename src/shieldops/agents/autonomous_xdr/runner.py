"""AutonomousXDRRunner — entry point for executing
vendor-neutral autonomous XDR workflows.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_xdr.graph import (
    build_graph,
)
from shieldops.agents.autonomous_xdr.models import (
    AutonomousXDRState,
)
from shieldops.agents.autonomous_xdr.nodes import (
    set_toolkit,
)
from shieldops.agents.autonomous_xdr.tools import (
    AutonomousXDRToolkit,
)

logger = structlog.get_logger()


class AutonomousXDRRunner:
    """Runner for the Autonomous XDR Agent.

    Provides ``detect()`` as the primary entry point
    for vendor-neutral cross-domain threat detection.
    """

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutonomousXDRToolkit(
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = build_graph()
        self._app = graph.compile()
        self._results: dict[str, AutonomousXDRState] = {}
        logger.info("autonomous_xdr_runner.initialized")

    async def detect(
        self,
        tenant_id: str,
        time_range_hours: int = 24,
        domains: list[str] | None = None,
        vendors: list[str] | None = None,
        auto_respond: bool = True,
    ) -> AutonomousXDRState:
        """Run autonomous XDR detection workflow.

        Args:
            tenant_id: Tenant identifier.
            time_range_hours: Lookback window in hours.
            domains: Signal domains to query (all if
                None).
            vendors: Vendor sources to query (all if
                None).
            auto_respond: Whether to execute automated
                response actions.

        Returns:
            Final AutonomousXDRState with all pipeline
            results.
        """
        session_id = f"axdr-{uuid4().hex[:12]}"
        config: dict[str, Any] = {
            "time_range_hours": time_range_hours,
            "domains": domains,
            "vendors": vendors,
            "auto_respond": auto_respond,
        }

        initial_state = AutonomousXDRState(
            session_id=session_id,
            tenant_id=tenant_id,
            config=config,
        )

        logger.info(
            "autonomous_xdr_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            time_range_hours=time_range_hours,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "autonomous_xdr",
                    },
                },
            )
            final_state = AutonomousXDRState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "autonomous_xdr_runner.completed",
                session_id=session_id,
                duration_ms=(final_state.session_duration_ms),
                signals=len(final_state.signals_collected),
                campaigns=len(final_state.campaigns_detected),
            )
            return final_state

        except Exception as e:
            logger.error(
                "autonomous_xdr_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = AutonomousXDRState(
                session_id=session_id,
                tenant_id=tenant_id,
                config=config,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> AutonomousXDRState | None:
        """Retrieve a previous detection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all detection results."""
        return [
            {
                "session_id": sid,
                "tenant_id": st.tenant_id,
                "current_step": st.current_step,
                "campaigns": len(st.campaigns_detected),
                "signals": len(st.signals_collected),
                "coverage_pct": (st.detection_coverage_pct),
                "duration_ms": (st.session_duration_ms),
                "error": st.error,
            }
            for sid, st in self._results.items()
        ]

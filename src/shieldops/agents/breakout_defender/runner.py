"""Breakout Defender Agent runner — entry point for breakout defense workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.breakout_defender.graph import (
    create_breakout_defender_graph,
)
from shieldops.agents.breakout_defender.models import (
    BreakoutDefenderState,
)
from shieldops.agents.breakout_defender.nodes import (
    set_toolkit,
)
from shieldops.agents.breakout_defender.tools import (
    BreakoutDefenderToolkit,
)

logger = structlog.get_logger()


class BreakoutDefenderRunner:
    """Runner for the Breakout Defender Agent.

    Provides sub-5-minute breakout containment by
    orchestrating detection, lateral movement analysis,
    risk assessment, and automated containment.
    """

    def __init__(
        self,
        signal_collector: Any | None = None,
        lateral_analyzer: Any | None = None,
        containment_engine: Any | None = None,
        identity_service: Any | None = None,
        network_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BreakoutDefenderToolkit(
            signal_collector=signal_collector,
            lateral_analyzer=lateral_analyzer,
            containment_engine=containment_engine,
            identity_service=identity_service,
            network_service=network_service,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_breakout_defender_graph()
        self._app = graph.compile()
        self._results: dict[str, BreakoutDefenderState] = {}
        logger.info(
            "breakout_defender_runner.initialized",
        )

    async def defend(
        self,
        tenant_id: str,
        signals: list[dict[str, Any]],
        defense_id: str | None = None,
    ) -> BreakoutDefenderState:
        """Run breakout defense workflow.

        Args:
            tenant_id: Tenant identifier.
            signals: Raw security signals to analyze.
            defense_id: Optional defense engagement ID.

        Returns:
            Final BreakoutDefenderState with report.
        """
        session_id = f"bd-{uuid4().hex[:12]}"
        did = defense_id or f"def-{uuid4().hex[:8]}"

        initial_state = BreakoutDefenderState(
            tenant_id=tenant_id,
            defense_id=did,
            incoming_signals=signals,
        )

        logger.info(
            "breakout_defender_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            defense_id=did,
            signal_count=len(signals),
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "breakout_defender",
                    },
                },
            )
            final_state = BreakoutDefenderState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "breakout_defender_runner.completed",
                session_id=session_id,
                prevented=final_state.breakout_prevented,
                ttc=final_state.time_to_contain_seconds,
                signals=len(final_state.signals),
                orders=len(
                    final_state.containment_orders,
                ),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "breakout_defender_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = BreakoutDefenderState(
                tenant_id=tenant_id,
                defense_id=did,
                incoming_signals=signals,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> BreakoutDefenderState | None:
        """Get result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all defense engagement results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "defense_id": state.defense_id,
                "prevented": state.breakout_prevented,
                "ttc_seconds": (state.time_to_contain_seconds),
                "signal_count": len(state.signals),
                "containment_count": len(
                    state.containment_orders,
                ),
                "risk_score": state.breakout_risk_score,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

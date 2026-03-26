"""Disaster Recovery Agent runner — entry point for executing DR workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.disaster_recovery.graph import create_disaster_recovery_graph
from shieldops.agents.disaster_recovery.models import DisasterRecoveryState
from shieldops.agents.disaster_recovery.nodes import set_toolkit
from shieldops.agents.disaster_recovery.tools import DisasterRecoveryToolkit

logger = structlog.get_logger()


class DisasterRecoveryRunner:
    """Runner for the Disaster Recovery Agent."""

    def __init__(
        self,
        dr_engine: Any | None = None,
        failover_orchestrator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DisasterRecoveryToolkit(
            dr_engine=dr_engine,
            failover_orchestrator=failover_orchestrator,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_disaster_recovery_graph()
        self._app = graph.compile()
        self._results: dict[str, DisasterRecoveryState] = {}
        logger.info("disaster_recovery_runner.initialized")

    async def test(
        self,
        tenant_id: str,
        plan_ids: list[str] | None = None,
    ) -> DisasterRecoveryState:
        """Run disaster recovery validation workflow.

        Assesses DR plans, executes failover tests, measures RTO/RPO,
        identifies gaps, remediates critical issues, and generates a report.
        """
        session_id = f"dr-{uuid4().hex[:12]}"
        initial_state = DisasterRecoveryState(
            tenant_id=tenant_id,
            plan_ids=plan_ids or [],
        )

        logger.info(
            "disaster_recovery_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={"metadata": {"session_id": session_id, "agent": "disaster_recovery"}},
            )
            final_state = DisasterRecoveryState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "disaster_recovery_runner.completed",
                session_id=session_id,
                plans_assessed=len(final_state.plans),
                gaps_found=len(final_state.gaps),
                rto_met=final_state.rto_met,
                rpo_met=final_state.rpo_met,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error("disaster_recovery_runner.failed", session_id=session_id, error=str(e))
            error_state = DisasterRecoveryState(
                tenant_id=tenant_id,
                plan_ids=plan_ids or [],
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> DisasterRecoveryState | None:
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "plans_assessed": len(state.plans),
                "gaps_found": len(state.gaps),
                "rto_met": state.rto_met,
                "rpo_met": state.rpo_met,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

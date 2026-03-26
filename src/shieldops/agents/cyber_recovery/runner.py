"""Cyber Recovery Agent runner — entry point for executing recovery workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cyber_recovery.graph import (
    create_cyber_recovery_graph,
)
from shieldops.agents.cyber_recovery.models import (
    CyberRecoveryState,
    RecoveryType,
)
from shieldops.agents.cyber_recovery.nodes import (
    set_toolkit,
)
from shieldops.agents.cyber_recovery.tools import (
    CyberRecoveryToolkit,
)

logger = structlog.get_logger()


class CyberRecoveryRunner:
    """Runner for the Cyber Recovery Agent."""

    def __init__(
        self,
        backup_engine: Any | None = None,
        scanner_engine: Any | None = None,
        restore_orchestrator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CyberRecoveryToolkit(
            backup_engine=backup_engine,
            scanner_engine=scanner_engine,
            restore_orchestrator=restore_orchestrator,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cyber_recovery_graph()
        self._app = graph.compile()
        self._results: dict[str, CyberRecoveryState] = {}
        logger.info("cyber_recovery_runner.initialized")

    async def recover(
        self,
        tenant_id: str,
        incident_id: str,
        recovery_type: RecoveryType = RecoveryType.FULL_RESTORE,
        rto_target_seconds: float = 3600.0,
        rpo_target_seconds: float = 900.0,
    ) -> CyberRecoveryState:
        """Run the cyber recovery workflow.

        Assesses damage, selects recovery points, validates
        in clean room, executes recovery, verifies integrity,
        and generates a compliance-ready report.
        """
        session_id = f"cr-{uuid4().hex[:12]}"
        initial_state = CyberRecoveryState(
            tenant_id=tenant_id,
            incident_id=incident_id,
            recovery_type=recovery_type,
            rto_target_seconds=rto_target_seconds,
            rpo_target_seconds=rpo_target_seconds,
        )

        logger.info(
            "cyber_recovery_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            recovery_type=recovery_type.value,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "cyber_recovery",
                    }
                },
            )
            final_state = CyberRecoveryState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "cyber_recovery_runner.completed",
                session_id=session_id,
                recovery_success=final_state.recovery_success,
                integrity_verified=(final_state.integrity_verified),
                rto_seconds=final_state.rto_seconds,
                rpo_seconds=final_state.rpo_seconds,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "cyber_recovery_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = CyberRecoveryState(
                tenant_id=tenant_id,
                incident_id=incident_id,
                recovery_type=recovery_type,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> CyberRecoveryState | None:
        """Retrieve a completed recovery result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all recovery workflow results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "incident_id": state.incident_id,
                "recovery_type": state.recovery_type.value,
                "recovery_success": state.recovery_success,
                "integrity_verified": (state.integrity_verified),
                "rto_seconds": state.rto_seconds,
                "rpo_seconds": state.rpo_seconds,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

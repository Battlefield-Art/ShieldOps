"""Security Training Platform runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_training_platform.graph import (
    create_security_training_platform_graph,
)
from shieldops.agents.security_training_platform.models import (
    SecurityTrainingPlatformState,
)
from shieldops.agents.security_training_platform.nodes import (
    set_toolkit,
)
from shieldops.agents.security_training_platform.tools import (
    SecurityTrainingPlatformToolkit,
)

logger = structlog.get_logger()


class SecurityTrainingPlatformRunner:
    """Runner for the Security Training Platform Agent."""

    def __init__(
        self,
        user_directory: Any | None = None,
        email_sender: Any | None = None,
        lms_client: Any | None = None,
        risk_engine: Any | None = None,
        analytics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityTrainingPlatformToolkit(
            user_directory=user_directory,
            email_sender=email_sender,
            lms_client=lms_client,
            risk_engine=risk_engine,
            analytics_store=analytics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_training_platform_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityTrainingPlatformState] = {}
        logger.info("stp_runner.initialized")

    async def train(
        self,
        request_id: str,
        tenant_id: str = "",
        training_config: dict[str, Any] | None = None,
    ) -> SecurityTrainingPlatformState:
        """Run security training workflow."""
        sid = f"stp-{uuid4().hex[:12]}"
        initial = SecurityTrainingPlatformState(
            request_id=request_id,
            tenant_id=tenant_id,
            training_config=training_config or {},
        )

        logger.info(
            "stp_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_training_platform",
                    },
                },
            )
            final = SecurityTrainingPlatformState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "stp_runner.completed",
                session_id=sid,
                teams=len(final.baseline_assessments),
                campaigns=len(final.campaigns),
                click_rate=final.overall_click_rate,
                high_risk=final.high_risk_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "stp_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecurityTrainingPlatformState(
                request_id=request_id,
                tenant_id=tenant_id,
                training_config=training_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> SecurityTrainingPlatformState | None:
        """Retrieve a previous training result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all training results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "teams_assessed": len(s.baseline_assessments),
                "campaigns": len(s.campaigns),
                "targeted_users": s.total_targeted_users,
                "click_rate": s.overall_click_rate,
                "high_risk": s.high_risk_count,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

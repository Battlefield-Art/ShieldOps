"""Data Security Posture Agent runner — entry point for
executing DSPM assessment workflows.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_security_posture.graph import (
    create_data_security_posture_graph,
)
from shieldops.agents.data_security_posture.models import (
    DataSecurityPostureState,
)
from shieldops.agents.data_security_posture.nodes import (
    set_toolkit,
)
from shieldops.agents.data_security_posture.tools import (
    DataSecurityPostureToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class DataSecurityPostureRunner:
    """Runner for the Data Security Posture Agent."""

    def __init__(
        self,
        data_scanner: Any | None = None,
        classifier: Any | None = None,
        risk_engine: Any | None = None,
        control_engine: Any | None = None,
        validator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataSecurityPostureToolkit(
            data_scanner=data_scanner,
            classifier=classifier,
            risk_engine=risk_engine,
            control_engine=control_engine,
            validator=validator,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_data_security_posture_graph()
        self._app = graph.compile()
        self._results: dict[str, DataSecurityPostureState] = {}
        logger.info("dsp_runner.initialized")

    @enforced("data_security_posture")
    async def run(
        self,
        tenant_id: str,
        request_id: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> DataSecurityPostureState:
        """Run data security posture assessment.

        Args:
            tenant_id: Tenant identifier.
            request_id: Optional request ID.
            config: Optional scan configuration.

        Returns:
            Final DataSecurityPostureState with all
            discovered stores, classifications, risks,
            controls, and posture score.
        """
        session_id = f"dsp-{uuid4().hex[:12]}"
        rid = request_id or f"dsp-{uuid4().hex[:8]}"
        initial_state = DataSecurityPostureState(
            request_id=rid,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "dsp_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            request_id=rid,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "data_security_posture",
                    },
                },
            )
            final_state = DataSecurityPostureState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "dsp_runner.completed",
                session_id=session_id,
                total_stores=final_state.total_stores,
                sensitive=final_state.sensitive_store_count,
                high_risk=final_state.high_risk_count,
                posture=final_state.posture_score,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "dsp_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = DataSecurityPostureState(
                request_id=rid,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> DataSecurityPostureState | None:
        """Retrieve a previous assessment result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all assessment results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "request_id": state.request_id,
                "total_stores": state.total_stores,
                "sensitive_stores": (state.sensitive_store_count),
                "high_risk_count": state.high_risk_count,
                "posture_score": state.posture_score,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

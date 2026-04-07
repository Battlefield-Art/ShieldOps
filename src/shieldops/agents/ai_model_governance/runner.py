"""AI Model Governance runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_model_governance.graph import (
    create_ai_model_governance_graph,
)
from shieldops.agents.ai_model_governance.models import (
    AIModelGovernanceState,
)
from shieldops.agents.ai_model_governance.nodes import (
    set_toolkit,
)
from shieldops.agents.ai_model_governance.tools import (
    AIModelGovernanceToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AIModelGovernanceRunner:
    """Runner for the AI Model Governance Agent."""

    def __init__(
        self,
        model_registry: Any | None = None,
        risk_engine: Any | None = None,
        bias_scanner: Any | None = None,
        compliance_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AIModelGovernanceToolkit(
            model_registry=model_registry,
            risk_engine=risk_engine,
            bias_scanner=bias_scanner,
            compliance_engine=compliance_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_ai_model_governance_graph()
        self._app = graph.compile()
        self._results: dict[str, AIModelGovernanceState] = {}
        logger.info("amg_runner.initialized")

    @enforced("ai_model_governance")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        governance_config: dict[str, Any] | None = None,
    ) -> AIModelGovernanceState:
        """Run AI model governance workflow."""
        sid = f"amg-{uuid4().hex[:12]}"
        initial = AIModelGovernanceState(
            request_id=request_id,
            tenant_id=tenant_id,
            governance_config=governance_config or {},
        )

        logger.info(
            "amg_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "ai_model_governance",
                    },
                },
            )
            final = AIModelGovernanceState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "amg_runner.completed",
                session_id=sid,
                models=final.total_models,
                high_risk=final.high_risk_count,
                bias=final.bias_detected_count,
                non_compliant=final.non_compliant_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "amg_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = AIModelGovernanceState(
                request_id=request_id,
                tenant_id=tenant_id,
                governance_config=governance_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> AIModelGovernanceState | None:
        """Retrieve a previous governance result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all governance results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_models": s.total_models,
                "high_risk": s.high_risk_count,
                "bias_detected": s.bias_detected_count,
                "non_compliant": s.non_compliant_count,
                "policy_actions": len(s.policy_actions),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

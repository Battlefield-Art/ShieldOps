"""Security Policy Optimizer runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_policy_optimizer.graph import (
    create_security_policy_optimizer_graph,
)
from shieldops.agents.security_policy_optimizer.models import (
    SecurityPolicyOptimizerState,
)
from shieldops.agents.security_policy_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.security_policy_optimizer.tools import (
    SecurityPolicyOptimizerToolkit,
)

logger = structlog.get_logger()


class SecurityPolicyOptimizerRunner:
    """Runner for the Security Policy Optimizer Agent."""

    def __init__(
        self,
        policy_store: Any | None = None,
        telemetry_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityPolicyOptimizerToolkit(
            policy_store=policy_store,
            telemetry_client=telemetry_client,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_policy_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityPolicyOptimizerState] = {}
        logger.info("spo_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityPolicyOptimizerState:
        """Run policy optimization workflow."""
        sid = f"spo-{uuid4().hex[:12]}"
        initial = SecurityPolicyOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "spo_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_policy_optimizer",
                    },
                },
            )
            final = SecurityPolicyOptimizerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "spo_runner.completed",
                session_id=sid,
                policies=len(final.policies),
                optimizations=len(final.optimizations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("spo_runner.failed", session_id=sid, error=str(e))
            err_state = SecurityPolicyOptimizerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> SecurityPolicyOptimizerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "policies": len(s.policies),
                "optimizations": len(s.optimizations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

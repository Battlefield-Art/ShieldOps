"""Security Chaos Orchestrator runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_chaos_orchestrator.graph import (
    create_security_chaos_orchestrator_graph,
)
from shieldops.agents.security_chaos_orchestrator.models import (
    SecurityChaosOrchestratorState,
)
from shieldops.agents.security_chaos_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.security_chaos_orchestrator.tools import (
    SecurityChaosOrchestratorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityChaosOrchestratorRunner:
    """Runner for the Security Chaos Orchestrator Agent."""

    def __init__(
        self,
        chaos_client: Any | None = None,
        monitoring_client: Any | None = None,
        service_registry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityChaosOrchestratorToolkit(
            infra_client=chaos_client,
            monitoring_client=monitoring_client,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_chaos_orchestrator_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityChaosOrchestratorState] = {}
        logger.info("sco_runner.initialized")

    @enforced("security_chaos_orchestrator")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityChaosOrchestratorState:
        """Run chaos orchestration workflow."""
        sid = f"sco-{uuid4().hex[:12]}"
        initial = SecurityChaosOrchestratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "sco_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_chaos_orchestrator",
                    },
                },
            )
            final = SecurityChaosOrchestratorState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "sco_runner.completed",
                session_id=sid,
                experiments=len(final.experiments),
                assessments=len(final.assessments),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sco_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecurityChaosOrchestratorState(
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
    ) -> SecurityChaosOrchestratorState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "experiments": len(s.experiments),
                "assessments": len(s.assessments),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

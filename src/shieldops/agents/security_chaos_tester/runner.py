"""Security Chaos Tester Agent runner — entry point
for executing security chaos campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_chaos_tester.graph import (
    create_security_chaos_tester_graph,
)
from shieldops.agents.security_chaos_tester.models import (
    FaultType,
    SecurityChaosState,
)
from shieldops.agents.security_chaos_tester.nodes import (
    set_toolkit,
)
from shieldops.agents.security_chaos_tester.tools import (
    SecurityChaosToolkit,
)

logger = structlog.get_logger()


class SecurityChaosRunner:
    """Runner for the Security Chaos Tester Agent."""

    def __init__(
        self,
        fault_injector: Any | None = None,
        monitor_connector: Any | None = None,
        resilience_scorer: Any | None = None,
        rollback_engine: Any | None = None,
        alert_verifier: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityChaosToolkit(
            fault_injector=fault_injector,
            monitor_connector=monitor_connector,
            resilience_scorer=resilience_scorer,
            rollback_engine=rollback_engine,
            alert_verifier=alert_verifier,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_chaos_tester_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityChaosState] = {}
        logger.info("sct_runner.initialized")

    async def test(
        self,
        experiment_name: str,
        fault_types: list[str] | None = None,
        target_components: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityChaosState:
        """Run a security chaos testing campaign."""
        request_id = f"sct-{uuid4().hex[:12]}"

        faults = [FaultType(f) for f in (fault_types or []) if f in FaultType.__members__.values()]

        initial_state = SecurityChaosState(
            request_id=request_id,
            tenant_id=tenant_id,
            experiment_name=experiment_name,
            fault_types=faults,
            target_components=(target_components or []),
            scope=scope or {},
        )

        logger.info(
            "sct_runner.starting",
            request_id=request_id,
            experiment=experiment_name,
            faults=len(faults),
            targets=len(target_components or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_chaos_tester",
                    },
                },
            )
            final = SecurityChaosState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sct_runner.completed",
                request_id=request_id,
                experiments=final.total_experiments,
                faults=final.total_faults_injected,
                resilience=final.avg_resilience_score,
                critical=final.critical_failures,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sct_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityChaosState(
                request_id=request_id,
                tenant_id=tenant_id,
                experiment_name=experiment_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityChaosState | None:
        """Retrieve a cached campaign result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all campaign results as summaries."""
        return [
            {
                "request_id": rid,
                "experiment": s.experiment_name,
                "experiments": s.total_experiments,
                "faults": s.total_faults_injected,
                "resilience": s.avg_resilience_score,
                "critical": s.critical_failures,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

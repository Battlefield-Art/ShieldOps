"""Security Simulation Sandbox Agent runner — entry point
for executing isolated security tests."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_simulation_sandbox.graph import (
    create_security_simulation_sandbox_graph,
)
from shieldops.agents.security_simulation_sandbox.models import (
    SandboxType,
    SecuritySimulationSandboxState,
)
from shieldops.agents.security_simulation_sandbox.nodes import (
    set_toolkit,
)
from shieldops.agents.security_simulation_sandbox.tools import (
    SecuritySimulationSandboxToolkit,
)

logger = structlog.get_logger()


class SecuritySimulationSandboxRunner:
    """Runner for the Security Simulation Sandbox Agent."""

    def __init__(
        self,
        sandbox_provider: Any | None = None,
        scenario_engine: Any | None = None,
        artifact_collector: Any | None = None,
        detection_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecuritySimulationSandboxToolkit(
            sandbox_provider=sandbox_provider,
            scenario_engine=scenario_engine,
            artifact_collector=artifact_collector,
            detection_engine=detection_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_simulation_sandbox_graph()
        self._app = graph.compile()
        self._results: dict[str, SecuritySimulationSandboxState] = {}
        logger.info("sss_runner.initialized")

    async def run_simulation(
        self,
        sandbox_name: str,
        sandbox_type: str = "attack_simulation",
        scenarios: list[dict[str, Any]] | None = None,
        target_environment: str = "default",
        isolation_level: str = "full",
        tenant_id: str = "",
    ) -> SecuritySimulationSandboxState:
        """Run a security simulation in an isolated sandbox."""
        request_id = f"sss-{uuid4().hex[:12]}"

        initial_state = SecuritySimulationSandboxState(
            request_id=request_id,
            tenant_id=tenant_id,
            sandbox_name=sandbox_name,
            sandbox_type=SandboxType(sandbox_type),
            scenarios=scenarios or [],
            target_environment=target_environment,
            isolation_level=isolation_level,
        )

        logger.info(
            "sss_runner.starting",
            request_id=request_id,
            sandbox_name=sandbox_name,
            sandbox_type=sandbox_type,
            scenarios=len(scenarios or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_simulation_sandbox",
                    },
                },
            )
            final = SecuritySimulationSandboxState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "sss_runner.completed",
                request_id=request_id,
                tests_passed=final.tests_passed,
                tests_failed=final.tests_failed,
                coverage=final.detection_coverage,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sss_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecuritySimulationSandboxState(
                request_id=request_id,
                tenant_id=tenant_id,
                sandbox_name=sandbox_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecuritySimulationSandboxState | None:
        """Retrieve a cached simulation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all simulation results as summaries."""
        return [
            {
                "request_id": rid,
                "sandbox_name": s.sandbox_name,
                "sandbox_type": s.sandbox_type.value,
                "tests_passed": s.tests_passed,
                "tests_failed": s.tests_failed,
                "coverage": s.detection_coverage,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

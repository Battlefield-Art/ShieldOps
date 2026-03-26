"""Digital Twin Security Agent runner — entry point for executing simulations."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.digital_twin_security.graph import build_graph
from shieldops.agents.digital_twin_security.models import DigitalTwinSecurityState
from shieldops.agents.digital_twin_security.nodes import set_toolkit
from shieldops.agents.digital_twin_security.tools import DigitalTwinSecurityToolkit

logger = structlog.get_logger()


class DigitalTwinSecurityRunner:
    """Runner for the Digital Twin Security Agent."""

    def __init__(
        self,
        cloud_connector: Any | None = None,
        network_scanner: Any | None = None,
        identity_provider: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DigitalTwinSecurityToolkit(
            cloud_connector=cloud_connector,
            network_scanner=network_scanner,
            identity_provider=identity_provider,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = build_graph(self._toolkit)
        self._app = graph.compile()
        self._results: dict[str, DigitalTwinSecurityState] = {}
        logger.info("digital_twin_security_runner.initialized")

    async def simulate(
        self,
        tenant_id: str,
        twin_config: dict[str, Any],
        scenarios: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> DigitalTwinSecurityState:
        """Run a digital twin security simulation campaign.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            twin_config: Configuration for the digital twin (type, components,
                network topology, security controls, etc.).
            scenarios: List of scenario categories to execute. If None, all
                scenarios are executed.
            context: Additional context for the simulation.

        Returns:
            Final DigitalTwinSecurityState with results and posture assessment.
        """
        session_id = f"dtsec-{uuid4().hex[:12]}"
        ctx = context or {}

        initial_state = DigitalTwinSecurityState(
            tenant_id=tenant_id,
            twin_config=twin_config,
            scenarios_requested=scenarios or [],
        )

        logger.info(
            "digital_twin_security_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            twin_type=twin_config.get("twin_type", "infrastructure"),
            scenario_count=len(scenarios) if scenarios else "all",
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "digital_twin_security",
                        "tenant_id": tenant_id,
                        **ctx,
                    }
                },
            )
            final_state = DigitalTwinSecurityState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "digital_twin_security_runner.completed",
                session_id=session_id,
                verdict=final_state.verdict,
                risk_score=final_state.overall_risk_score,
                scenarios_executed=len(final_state.scenarios),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "digital_twin_security_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = DigitalTwinSecurityState(
                tenant_id=tenant_id,
                twin_config=twin_config,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> DigitalTwinSecurityState | None:
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "verdict": state.verdict,
                "overall_risk_score": state.overall_risk_score,
                "scenarios_executed": len(state.scenarios),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

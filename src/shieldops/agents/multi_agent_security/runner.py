"""Multi-Agent Security Agent runner — entry point for executing security scans."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.multi_agent_security.graph import build_graph
from shieldops.agents.multi_agent_security.models import MultiAgentSecurityState
from shieldops.agents.multi_agent_security.tools import MultiAgentSecurityToolkit

logger = structlog.get_logger()


class MultiAgentSecurityRunner:
    """Runner for the Multi-Agent Security Agent."""

    def __init__(
        self,
        identity_registry: Any | None = None,
        policy_engine: Any | None = None,
        message_bus: Any | None = None,
        telemetry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MultiAgentSecurityToolkit(
            identity_registry=identity_registry,
            policy_engine=policy_engine,
            message_bus=message_bus,
            telemetry=telemetry,
            repository=repository,
        )
        graph = build_graph(self._toolkit)
        self._app = graph.compile()
        self._results: dict[str, MultiAgentSecurityState] = {}
        logger.info("multi_agent_security_runner.initialized")

    async def analyze(
        self,
        tenant_id: str,
        scan_scope: dict[str, Any] | None = None,
        agent_registry: list[str] | None = None,
    ) -> MultiAgentSecurityState:
        """Run a multi-agent security analysis for a tenant.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            scan_scope: Optional scope dict (time_range, environments, channels).
            agent_registry: Optional list of known agent identifiers to verify against.

        Returns:
            Final ``MultiAgentSecurityState`` with report and risk score.
        """
        session_id = f"mas-{uuid4().hex[:12]}"
        scope = scan_scope or {}
        registry = agent_registry or []

        initial_state = MultiAgentSecurityState(
            tenant_id=tenant_id,
            scan_scope=scope,
            agent_registry=registry,
        )

        logger.info(
            "multi_agent_security_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            agent_count=len(registry),
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "multi_agent_security",
                        "tenant_id": tenant_id,
                    }
                },
            )
            final_state = MultiAgentSecurityState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "multi_agent_security_runner.completed",
                session_id=session_id,
                risk_score=final_state.risk_score,
                anomalies=len(final_state.anomalies),
                blocked=final_state.blocked_interactions,
                quarantined=len(final_state.quarantined_agents),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "multi_agent_security_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = MultiAgentSecurityState(
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> MultiAgentSecurityState | None:
        """Retrieve a previous scan result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all completed scan summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "risk_score": state.risk_score,
                "threats_detected": state.threats_detected,
                "anomalies": len(state.anomalies),
                "blocked_interactions": state.blocked_interactions,
                "quarantined_agents": state.quarantined_agents,
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

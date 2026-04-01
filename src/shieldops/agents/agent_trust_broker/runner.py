"""Agent Trust Broker runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.agent_trust_broker.graph import (
    create_agent_trust_broker_graph,
)
from shieldops.agents.agent_trust_broker.models import (
    AgentTrustBrokerState,
)
from shieldops.agents.agent_trust_broker.nodes import (
    set_toolkit,
)
from shieldops.agents.agent_trust_broker.tools import (
    AgentTrustBrokerToolkit,
)

logger = structlog.get_logger()


class AgentTrustBrokerRunner:
    """Runner for the Agent Trust Broker Agent."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        identity_service: Any | None = None,
        behavior_monitor: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AgentTrustBrokerToolkit(
            agent_registry=agent_registry,
            identity_service=identity_service,
            behavior_monitor=behavior_monitor,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_agent_trust_broker_graph()
        self._app = graph.compile()
        self._results: dict[str, AgentTrustBrokerState] = {}
        logger.info("atb_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AgentTrustBrokerState:
        """Run agent trust brokering workflow."""
        sid = f"atb-{uuid4().hex[:12]}"
        initial = AgentTrustBrokerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "atb_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "agent_trust_broker",
                    },
                },
            )
            final = AgentTrustBrokerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "atb_runner.completed",
                session_id=sid,
                registered=len(final.registrations),
                revocations=len(final.revocations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "atb_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = AgentTrustBrokerState(
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
    ) -> AgentTrustBrokerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "registered": len(s.registrations),
                "revocations": len(s.revocations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

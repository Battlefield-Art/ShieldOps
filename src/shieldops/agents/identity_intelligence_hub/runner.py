"""Identity Intelligence Hub Agent runner — entry point
for executing identity correlation workflows.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.identity_intelligence_hub.graph import (
    create_identity_intelligence_hub_graph,
)
from shieldops.agents.identity_intelligence_hub.models import (
    IdentityIntelligenceHubState,
)
from shieldops.agents.identity_intelligence_hub.nodes import (
    set_toolkit,
)
from shieldops.agents.identity_intelligence_hub.tools import (
    IdentityIntelligenceHubToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IdentityIntelligenceHubRunner:
    """Runner for the Identity Intelligence Hub Agent."""

    def __init__(
        self,
        idp_connector: Any | None = None,
        iam_connector: Any | None = None,
        agent_registry: Any | None = None,
        threat_engine: Any | None = None,
        risk_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IdentityIntelligenceHubToolkit(
            idp_connector=idp_connector,
            iam_connector=iam_connector,
            agent_registry=agent_registry,
            threat_engine=threat_engine,
            risk_engine=risk_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_identity_intelligence_hub_graph()
        self._app = graph.compile()
        self._results: dict[str, IdentityIntelligenceHubState] = {}
        logger.info("iih_runner.initialized")

    @enforced("identity_intelligence_hub")
    async def run(
        self,
        tenant_id: str,
        request_id: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> IdentityIntelligenceHubState:
        """Run identity intelligence analysis.

        Args:
            tenant_id: Tenant identifier.
            request_id: Optional request ID.
            config: Optional configuration with sources
                and scope.

        Returns:
            Final IdentityIntelligenceHubState with all
            signals, correlations, threats, and actions.
        """
        session_id = f"iih-{uuid4().hex[:12]}"
        rid = request_id or f"iih-{uuid4().hex[:8]}"
        initial_state = IdentityIntelligenceHubState(
            request_id=rid,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "iih_runner.starting",
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
                        "agent": ("identity_intelligence_hub"),
                    },
                },
            )
            final_state = IdentityIntelligenceHubState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "iih_runner.completed",
                session_id=session_id,
                signals=final_state.total_signals,
                correlated=final_state.correlated_count,
                threats=final_state.threat_count,
                high_risk=(final_state.high_risk_identities),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "iih_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = IdentityIntelligenceHubState(
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
    ) -> IdentityIntelligenceHubState | None:
        """Retrieve a previous analysis result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "request_id": state.request_id,
                "total_signals": state.total_signals,
                "correlated_count": (state.correlated_count),
                "threat_count": state.threat_count,
                "high_risk_identities": (state.high_risk_identities),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

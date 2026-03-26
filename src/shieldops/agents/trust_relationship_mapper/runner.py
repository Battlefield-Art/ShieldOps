"""Trust Relationship Mapper Agent runner."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.trust_relationship_mapper.graph import (
    create_trust_relationship_mapper_graph,
)
from shieldops.agents.trust_relationship_mapper.models import (
    TrustRelationshipMapperState,
)
from shieldops.agents.trust_relationship_mapper.nodes import (
    set_toolkit,
)
from shieldops.agents.trust_relationship_mapper.tools import (
    TrustRelationshipMapperToolkit,
)

logger = structlog.get_logger()


class TrustRelationshipMapperRunner:
    """Runner for the Trust Relationship Mapper."""

    def __init__(
        self,
        identity_sources: Any | None = None,
        federation_scanner: Any | None = None,
        cloud_connectors: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = TrustRelationshipMapperToolkit(
            identity_sources=identity_sources,
            federation_scanner=(federation_scanner),
            cloud_connectors=cloud_connectors,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_trust_relationship_mapper_graph()
        self._app = graph.compile()
        self._results: dict[str, TrustRelationshipMapperState] = {}
        logger.info("trust_relationship_mapper_runner.initialized")

    async def map_trust(
        self,
        tenant_id: str,
        scope: str = "all",
    ) -> TrustRelationshipMapperState:
        """Run trust relationship mapping."""
        session_id = f"trm-{uuid4().hex[:12]}"
        initial = TrustRelationshipMapperState(
            tenant_id=tenant_id,
            scope=scope,
        )

        logger.info(
            "trust_relationship_mapper.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            scope=scope,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": ("trust_relationship_mapper"),
                    }
                },
            )
            final = TrustRelationshipMapperState.model_validate(result)
            self._results[session_id] = final

            logger.info(
                "trust_relationship_mapper.completed",
                session_id=session_id,
                boundaries=(final.total_boundaries),
                abuses=(final.total_abuses_detected),
                avg_risk=final.avg_risk_score,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "trust_relationship_mapper.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = TrustRelationshipMapperState(
                tenant_id=tenant_id,
                scope=scope,
                error=str(e),
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> TrustRelationshipMapperState | None:
        """Retrieve a stored result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all trust mapping summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "boundaries": s.total_boundaries,
                "abuses": (s.total_abuses_detected),
                "avg_risk": s.avg_risk_score,
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

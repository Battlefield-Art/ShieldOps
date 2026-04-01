"""Security Knowledge Graph runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_knowledge_graph.graph import (
    create_security_knowledge_graph_graph,
)
from shieldops.agents.security_knowledge_graph.models import (
    SecurityKnowledgeGraphState,
)
from shieldops.agents.security_knowledge_graph.nodes import (
    set_toolkit,
)
from shieldops.agents.security_knowledge_graph.tools import (
    SecurityKnowledgeGraphToolkit,
)

logger = structlog.get_logger()


class SecurityKnowledgeGraphRunner:
    """Runner for the Security Knowledge Graph Agent."""

    def __init__(
        self,
        graph_db_client: Any | None = None,
        threat_intel_client: Any | None = None,
        asset_inventory: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityKnowledgeGraphToolkit(
            graph_db_client=graph_db_client,
            threat_intel_client=threat_intel_client,
            asset_inventory=asset_inventory,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_knowledge_graph_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityKnowledgeGraphState] = {}
        logger.info("skg_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityKnowledgeGraphState:
        """Run knowledge graph workflow."""
        sid = f"skg-{uuid4().hex[:12]}"
        initial = SecurityKnowledgeGraphState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "skg_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_knowledge_graph",
                    },
                },
            )
            final = SecurityKnowledgeGraphState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "skg_runner.completed",
                session_id=sid,
                entities=len(final.entities),
                anomalies=len(final.anomalies),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("skg_runner.failed", session_id=sid, error=str(e))
            err_state = SecurityKnowledgeGraphState(
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
    ) -> SecurityKnowledgeGraphState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "entities": len(s.entities),
                "anomalies": len(s.anomalies),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

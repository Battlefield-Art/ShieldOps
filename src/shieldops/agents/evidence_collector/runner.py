"""Evidence Collector Agent runner -- entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.evidence_collector.graph import (
    create_evidence_collector_graph,
)
from shieldops.agents.evidence_collector.models import (
    EvidenceCollectorState,
)
from shieldops.agents.evidence_collector.nodes import (
    set_toolkit,
)
from shieldops.agents.evidence_collector.tools import (
    EvidenceCollectorToolkit,
)

logger = structlog.get_logger()


class EvidenceCollectorRunner:
    """Runner for the Evidence Collector Agent."""

    def __init__(
        self,
        forensics_client: Any | None = None,
        storage_client: Any | None = None,
    ) -> None:
        self._toolkit = EvidenceCollectorToolkit(
            forensics_client=forensics_client,
            storage_client=storage_client,
        )
        set_toolkit(self._toolkit)
        graph = create_evidence_collector_graph()
        self._app = graph.compile()
        self._results: dict[str, EvidenceCollectorState] = {}
        logger.info("evidence_collector_runner.initialized")

    async def execute(
        self,
        tenant_id: str,
        incident_id: str,
        incident_details: dict[str, Any] | None = None,
    ) -> EvidenceCollectorState:
        """Run evidence collection for an incident.

        Args:
            tenant_id: Tenant identifier.
            incident_id: Incident to collect evidence for.
            incident_details: Optional incident context
                (type, affected_hosts, etc.).

        Returns:
            Final state with collected evidence and report.
        """
        session_id = f"evidence-collector-{uuid4().hex[:12]}"
        initial_state = EvidenceCollectorState(
            request_id=session_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            incident_details=incident_details or {},
        )

        logger.info(
            "evidence_collector_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "evidence_collector",
                    }
                },
            )
            final_state = EvidenceCollectorState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "evidence_collector_runner.completed",
                session_id=session_id,
                sources=len(final_state.sources),
                artifacts=len(final_state.artifacts),
                verified=final_state.verified_count,
            )
            return final_state

        except Exception as e:
            logger.error(
                "evidence_collector_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = EvidenceCollectorState(
                request_id=session_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                error=str(e),
                stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> EvidenceCollectorState | None:
        """Retrieve a past collection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all collection results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "incident_id": state.incident_id,
                "artifacts": len(state.artifacts),
                "verified": state.verified_count,
                "stage": state.stage,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

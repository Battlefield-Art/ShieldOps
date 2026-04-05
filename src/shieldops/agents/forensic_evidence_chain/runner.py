"""Forensic Evidence Chain runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.forensic_evidence_chain.graph import (
    create_forensic_evidence_chain_graph,
)
from shieldops.agents.forensic_evidence_chain.models import (
    ForensicEvidenceChainState,
)
from shieldops.agents.forensic_evidence_chain.nodes import (
    set_toolkit,
)
from shieldops.agents.forensic_evidence_chain.tools import (
    ForensicEvidenceChainToolkit,
)

logger = structlog.get_logger()


class ForensicEvidenceChainRunner:
    """Runner for the Forensic Evidence Chain Agent."""

    def __init__(
        self,
        forensic_client: Any | None = None,
        storage_backend: Any | None = None,
        hash_service: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ForensicEvidenceChainToolkit(
            forensic_client=forensic_client,
            storage_backend=storage_backend,
            hash_service=hash_service,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_forensic_evidence_chain_graph()
        self._app = graph.compile()
        self._results: dict[str, ForensicEvidenceChainState] = {}
        logger.info("fec_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ForensicEvidenceChainState:
        """Run forensic evidence chain workflow."""
        sid = f"fec-{uuid4().hex[:12]}"
        initial = ForensicEvidenceChainState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "fec_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "forensic_evidence_chain",
                    },
                },
            )
            final = ForensicEvidenceChainState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "fec_runner.completed",
                session_id=sid,
                evidence=len(final.evidence_items),
                packages=len(final.legal_packages),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "fec_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ForensicEvidenceChainState(
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
    ) -> ForensicEvidenceChainState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "evidence": len(s.evidence_items),
                "packages": len(s.legal_packages),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

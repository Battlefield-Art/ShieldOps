"""Compliance Evidence Generator — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_evidence_generator.graph import (
    create_compliance_evidence_generator_graph,
)
from shieldops.agents.compliance_evidence_generator.models import (
    ComplianceEvidenceGeneratorState,
)
from shieldops.agents.compliance_evidence_generator.nodes import (
    set_toolkit,
)
from shieldops.agents.compliance_evidence_generator.tools import (
    ComplianceEvidenceGeneratorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ComplianceEvidenceGeneratorRunner:
    """Runner for the Compliance Evidence Generator Agent."""

    def __init__(
        self,
        telemetry_client: Any | None = None,
        config_store: Any | None = None,
        evidence_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceEvidenceGeneratorToolkit(
            telemetry_client=telemetry_client,
            config_store=config_store,
            evidence_store=evidence_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_compliance_evidence_generator_graph()
        self._app = graph.compile()
        self._results: dict[str, ComplianceEvidenceGeneratorState] = {}
        logger.info("ceg_runner.initialized")

    @enforced("compliance_evidence_generator")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ComplianceEvidenceGeneratorState:
        """Run the compliance evidence generation workflow."""
        sid = f"ceg-{uuid4().hex[:12]}"
        initial = ComplianceEvidenceGeneratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {"frameworks": ["soc2"]},
        )

        logger.info(
            "ceg_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "compliance_evidence_generator",
                    },
                },
            )
            final = ComplianceEvidenceGeneratorState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "ceg_runner.completed",
                session_id=sid,
                controls=len(final.controls),
                evidence=len(final.evidence),
                gaps=len(final.gaps),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("ceg_runner.failed", session_id=sid, error=str(e))
            err_state = ComplianceEvidenceGeneratorState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {"frameworks": ["soc2"]},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> ComplianceEvidenceGeneratorState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "controls": len(s.controls),
                "evidence": len(s.evidence),
                "gaps": len(s.gaps),
                "packages": len(s.packages),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

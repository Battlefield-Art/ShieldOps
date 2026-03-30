"""Compliance Evidence Collector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_evidence_collector.graph import (
    create_compliance_evidence_collector_graph,
)
from shieldops.agents.compliance_evidence_collector.models import (
    ComplianceEvidenceCollectorState,
)
from shieldops.agents.compliance_evidence_collector.nodes import (
    set_toolkit,
)
from shieldops.agents.compliance_evidence_collector.tools import (
    ComplianceEvidenceCollectorToolkit,
)

logger = structlog.get_logger()


class ComplianceEvidenceCollectorRunner:
    """Runner for the Compliance Evidence Collector Agent."""

    def __init__(
        self,
        log_collector: Any | None = None,
        config_scanner: Any | None = None,
        policy_store: Any | None = None,
        screenshot_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceEvidenceCollectorToolkit(
            log_collector=log_collector,
            config_scanner=config_scanner,
            policy_store=policy_store,
            screenshot_engine=screenshot_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_compliance_evidence_collector_graph()
        self._app = graph.compile()
        self._results: dict[str, ComplianceEvidenceCollectorState] = {}
        logger.info("evidence_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> ComplianceEvidenceCollectorState:
        """Run compliance evidence collection workflow."""
        sid = f"evidence-{uuid4().hex[:12]}"
        initial = ComplianceEvidenceCollectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "evidence_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "compliance_evidence_collector",
                    },
                },
            )
            final = ComplianceEvidenceCollectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "evidence_runner.completed",
                session_id=sid,
                controls=final.total_controls,
                collected=final.collected_count,
                valid=final.valid_count,
                coverage=final.coverage_pct,
                sections=len(final.report_sections),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "evidence_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ComplianceEvidenceCollectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_config=scan_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> ComplianceEvidenceCollectorState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_controls": s.total_controls,
                "collected": s.collected_count,
                "valid": s.valid_count,
                "coverage_pct": s.coverage_pct,
                "report_sections": len(s.report_sections),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

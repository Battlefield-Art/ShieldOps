"""Digital Forensics Lab Agent runner — entry point
for executing forensic investigations."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.digital_forensics_lab.graph import (
    create_digital_forensics_lab_graph,
)
from shieldops.agents.digital_forensics_lab.models import (
    DigitalForensicsLabState,
)
from shieldops.agents.digital_forensics_lab.nodes import (
    set_toolkit,
)
from shieldops.agents.digital_forensics_lab.tools import (
    DigitalForensicsLabToolkit,
)

logger = structlog.get_logger()


class DigitalForensicsLabRunner:
    """Runner for the Digital Forensics Lab Agent."""

    def __init__(
        self,
        evidence_acquirer: Any | None = None,
        artifact_analyzer: Any | None = None,
        ioc_extractor: Any | None = None,
        timeline_builder: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DigitalForensicsLabToolkit(
            evidence_acquirer=evidence_acquirer,
            artifact_analyzer=artifact_analyzer,
            ioc_extractor=ioc_extractor,
            timeline_builder=timeline_builder,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_digital_forensics_lab_graph()
        self._app = graph.compile()
        self._results: dict[str, DigitalForensicsLabState] = {}
        logger.info("dfl_runner.initialized")

    async def investigate(
        self,
        case_id: str,
        incident_id: str = "",
        target_hosts: list[str] | None = None,
        evidence_types: list[str] | None = None,
        tenant_id: str = "",
    ) -> DigitalForensicsLabState:
        """Run a digital forensics investigation."""
        request_id = f"dfl-{uuid4().hex[:12]}"

        initial_state = DigitalForensicsLabState(
            request_id=request_id,
            tenant_id=tenant_id,
            case_id=case_id,
            incident_id=incident_id,
            target_hosts=target_hosts or [],
            evidence_types=evidence_types or [],
        )

        logger.info(
            "dfl_runner.starting",
            request_id=request_id,
            case_id=case_id,
            incident_id=incident_id,
            hosts=len(target_hosts or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "digital_forensics_lab",
                    },
                },
            )
            final = DigitalForensicsLabState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "dfl_runner.completed",
                request_id=request_id,
                evidence=final.total_evidence,
                artifacts=final.total_artifacts,
                iocs=final.total_iocs,
                events=final.timeline_events,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dfl_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = DigitalForensicsLabState(
                request_id=request_id,
                tenant_id=tenant_id,
                case_id=case_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> DigitalForensicsLabState | None:
        """Retrieve a cached investigation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all investigation results as summaries."""
        return [
            {
                "request_id": rid,
                "case_id": s.case_id,
                "incident_id": s.incident_id,
                "evidence": s.total_evidence,
                "artifacts": s.total_artifacts,
                "iocs": s.total_iocs,
                "events": s.timeline_events,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

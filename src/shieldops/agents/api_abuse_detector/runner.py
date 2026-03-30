"""API Abuse Detector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.api_abuse_detector.graph import (
    create_api_abuse_detector_graph,
)
from shieldops.agents.api_abuse_detector.models import (
    ApiAbuseDetectorState,
)
from shieldops.agents.api_abuse_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.api_abuse_detector.tools import (
    ApiAbuseDetectorToolkit,
)

logger = structlog.get_logger()


class ApiAbuseDetectorRunner:
    """Runner for the API Abuse Detector Agent."""

    def __init__(
        self,
        traffic_collector: Any | None = None,
        pattern_analyzer: Any | None = None,
        threat_classifier: Any | None = None,
        waf_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ApiAbuseDetectorToolkit(
            traffic_collector=traffic_collector,
            pattern_analyzer=pattern_analyzer,
            threat_classifier=threat_classifier,
            waf_client=waf_client,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_api_abuse_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, ApiAbuseDetectorState] = {}
        logger.info("abuse_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> ApiAbuseDetectorState:
        """Run API abuse detection workflow."""
        sid = f"abuse-{uuid4().hex[:12]}"
        initial = ApiAbuseDetectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "abuse_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "api_abuse_detector",
                    },
                },
            )
            final = ApiAbuseDetectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "abuse_runner.completed",
                session_id=sid,
                patterns=len(final.abuse_patterns),
                threat_level=final.max_threat_level,
                mitigations=len(final.mitigations),
                blocked=final.blocked_sources,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "abuse_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ApiAbuseDetectorState(
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
    ) -> ApiAbuseDetectorState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_requests": s.total_requests,
                "anomaly_count": s.anomaly_count,
                "abuse_patterns": len(s.abuse_patterns),
                "max_threat_level": s.max_threat_level,
                "mitigations": len(s.mitigations),
                "blocked_sources": s.blocked_sources,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

"""Certificate Transparency Monitor Agent runner — entry
point for executing CT log monitoring sessions."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.certificate_transparency_monitor.graph import (
    create_certificate_transparency_monitor_graph,
)
from shieldops.agents.certificate_transparency_monitor.models import (
    CertificateTransparencyMonitorState,
)
from shieldops.agents.certificate_transparency_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.certificate_transparency_monitor.tools import (
    CertificateTransparencyMonitorToolkit,
)

logger = structlog.get_logger()


class CertificateTransparencyMonitorRunner:
    """Runner for the Certificate Transparency Monitor."""

    def __init__(
        self,
        ct_client: Any | None = None,
        cert_parser: Any | None = None,
        domain_intel: Any | None = None,
        ownership_checker: Any | None = None,
        alert_manager: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CertificateTransparencyMonitorToolkit(
            ct_client=ct_client,
            cert_parser=cert_parser,
            domain_intel=domain_intel,
            ownership_checker=ownership_checker,
            alert_manager=alert_manager,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_certificate_transparency_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, CertificateTransparencyMonitorState] = {}
        logger.info("ctm_runner.initialized")

    async def monitor(
        self,
        watched_domains: list[str],
        ct_log_sources: list[str] | None = None,
        sensitivity: str = "medium",
        tenant_id: str = "",
    ) -> CertificateTransparencyMonitorState:
        """Run a CT log monitoring session."""
        request_id = f"ctm-{uuid4().hex[:12]}"

        initial_state = CertificateTransparencyMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            watched_domains=watched_domains,
            ct_log_sources=ct_log_sources or [],
            sensitivity=sensitivity,
        )

        logger.info(
            "ctm_runner.starting",
            request_id=request_id,
            domains=len(watched_domains),
            sensitivity=sensitivity,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("certificate_transparency_monitor"),
                    },
                },
            )
            final = CertificateTransparencyMonitorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "ctm_runner.completed",
                request_id=request_id,
                certs_scanned=final.total_certs_scanned,
                anomalies=final.anomalies_found,
                alerts=final.alerts_sent,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ctm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CertificateTransparencyMonitorState(
                request_id=request_id,
                tenant_id=tenant_id,
                watched_domains=watched_domains,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CertificateTransparencyMonitorState | None:
        """Retrieve a cached monitoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all monitoring results as summaries."""
        return [
            {
                "request_id": rid,
                "domains": len(s.watched_domains),
                "certs_scanned": s.total_certs_scanned,
                "anomalies": s.anomalies_found,
                "alerts": s.alerts_sent,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

"""Wireless Security Auditor Agent runner — entry point
for executing wireless security audits."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.wireless_security_auditor.graph import (
    create_wireless_security_auditor_graph,
)
from shieldops.agents.wireless_security_auditor.models import (
    WirelessSecurityAuditorState,
)
from shieldops.agents.wireless_security_auditor.nodes import (
    set_toolkit,
)
from shieldops.agents.wireless_security_auditor.tools import (
    WirelessSecurityToolkit,
)

logger = structlog.get_logger()


class WirelessSecurityAuditorRunner:
    """Runner for the Wireless Security Auditor Agent."""

    def __init__(
        self,
        network_scanner: Any | None = None,
        ap_inventory: Any | None = None,
        encryption_checker: Any | None = None,
        rogue_detector: Any | None = None,
        risk_scorer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = WirelessSecurityToolkit(
            network_scanner=network_scanner,
            ap_inventory=ap_inventory,
            encryption_checker=encryption_checker,
            rogue_detector=rogue_detector,
            risk_scorer=risk_scorer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_wireless_security_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, WirelessSecurityAuditorState] = {}
        logger.info("wsa_runner.initialized")

    async def audit(
        self,
        site_name: str,
        known_ssids: list[str] | None = None,
        scan_scope: dict[str, Any] | None = None,
        compliance_standard: str = "wpa3",
        tenant_id: str = "",
    ) -> WirelessSecurityAuditorState:
        """Run a wireless security audit."""
        request_id = f"wsa-{uuid4().hex[:12]}"

        initial_state = WirelessSecurityAuditorState(
            request_id=request_id,
            tenant_id=tenant_id,
            site_name=site_name,
            known_ssids=known_ssids or [],
            scan_scope=scan_scope or {},
            compliance_standard=compliance_standard,
        )

        logger.info(
            "wsa_runner.starting",
            request_id=request_id,
            site=site_name,
            known_ssids=len(known_ssids or []),
            standard=compliance_standard,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("wireless_security_auditor"),
                    },
                },
            )
            final = WirelessSecurityAuditorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "wsa_runner.completed",
                request_id=request_id,
                networks=final.total_networks,
                aps=final.total_access_points,
                rogues=final.rogue_count,
                non_compliant=final.non_compliant_count,
                risk_score=final.risk_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "wsa_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = WirelessSecurityAuditorState(
                request_id=request_id,
                tenant_id=tenant_id,
                site_name=site_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> WirelessSecurityAuditorState | None:
        """Retrieve a cached audit result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all audit results as summaries."""
        return [
            {
                "request_id": rid,
                "site": s.site_name,
                "networks": s.total_networks,
                "aps": s.total_access_points,
                "rogues": s.rogue_count,
                "non_compliant": s.non_compliant_count,
                "risk_score": s.risk_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

"""Mobile Threat Defender runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.mobile_threat_defender.graph import (
    create_mobile_threat_defender_graph,
)
from shieldops.agents.mobile_threat_defender.models import (
    MobileThreatDefenderState,
)
from shieldops.agents.mobile_threat_defender.nodes import (
    set_toolkit,
)
from shieldops.agents.mobile_threat_defender.tools import (
    MobileThreatDefenderToolkit,
)

logger = structlog.get_logger()


class MobileThreatDefenderRunner:
    """Runner for the Mobile Threat Defender Agent."""

    def __init__(
        self,
        mdm_client: Any | None = None,
        app_reputation: Any | None = None,
        network_monitor: Any | None = None,
        threat_intel: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MobileThreatDefenderToolkit(
            mdm_client=mdm_client,
            app_reputation=app_reputation,
            network_monitor=network_monitor,
            threat_intel=threat_intel,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_mobile_threat_defender_graph()
        self._app = graph.compile()
        self._results: dict[str, MobileThreatDefenderState] = {}
        logger.info("mtd_runner.initialized")

    async def defend(
        self,
        request_id: str,
        tenant_id: str = "",
        defend_config: dict[str, Any] | None = None,
    ) -> MobileThreatDefenderState:
        """Run mobile threat defense workflow."""
        sid = f"mtd-{uuid4().hex[:12]}"
        initial = MobileThreatDefenderState(
            request_id=request_id,
            tenant_id=tenant_id,
            defend_config=defend_config or {},
        )

        logger.info(
            "mtd_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "mobile_threat_defender",
                    },
                },
            )
            final = MobileThreatDefenderState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "mtd_runner.completed",
                session_id=sid,
                devices=len(final.device_scans),
                threats=len(final.detected_threats),
                actions=len(final.policy_actions),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "mtd_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = MobileThreatDefenderState(
                request_id=request_id,
                tenant_id=tenant_id,
                defend_config=defend_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> MobileThreatDefenderState | None:
        """Retrieve a previous defense result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all defense results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "devices_scanned": len(s.device_scans),
                "compromised": s.compromised_device_count,
                "malicious_apps": s.malicious_app_count,
                "network_threats": s.network_threat_count,
                "total_threats": len(s.detected_threats),
                "max_severity": s.max_threat_severity,
                "policy_actions": len(s.policy_actions),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

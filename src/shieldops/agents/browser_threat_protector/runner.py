"""Browser Threat Protector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.browser_threat_protector.graph import (
    create_browser_threat_protector_graph,
)
from shieldops.agents.browser_threat_protector.models import (
    BrowserThreatProtectorState,
)
from shieldops.agents.browser_threat_protector.nodes import (
    set_toolkit,
)
from shieldops.agents.browser_threat_protector.tools import (
    BrowserThreatProtectorToolkit,
)

logger = structlog.get_logger()


class BrowserThreatProtectorRunner:
    """Runner for the Browser Threat Protector Agent."""

    def __init__(
        self,
        url_reputation: Any | None = None,
        isolation_engine: Any | None = None,
        content_scanner: Any | None = None,
        policy_engine: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BrowserThreatProtectorToolkit(
            url_reputation=url_reputation,
            isolation_engine=isolation_engine,
            content_scanner=content_scanner,
            policy_engine=policy_engine,
            threat_intel=threat_intel,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_browser_threat_protector_graph()
        self._app = graph.compile()
        self._results: dict[str, BrowserThreatProtectorState] = {}
        logger.info("btp_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        protection_config: dict[str, Any] | None = None,
    ) -> BrowserThreatProtectorState:
        """Run browser threat protection workflow."""
        sid = f"btp-{uuid4().hex[:12]}"
        initial = BrowserThreatProtectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            protection_config=protection_config or {},
        )

        logger.info(
            "btp_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "browser_threat_protector",
                    },
                },
            )
            final = BrowserThreatProtectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "btp_runner.completed",
                session_id=sid,
                requests=final.request_count,
                suspicious=final.suspicious_count,
                threats=final.threats_found,
                blocked=final.blocked_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "btp_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = BrowserThreatProtectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                protection_config=protection_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> BrowserThreatProtectorState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_requests": s.request_count,
                "suspicious": s.suspicious_count,
                "isolated": s.isolated_count,
                "threats": s.threats_found,
                "blocked": s.blocked_count,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

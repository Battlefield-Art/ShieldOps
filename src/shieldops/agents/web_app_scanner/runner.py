"""Web App Scanner Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.web_app_scanner.graph import (
    build_graph,
)
from shieldops.agents.web_app_scanner.models import (
    WebAppScannerState,
)
from shieldops.agents.web_app_scanner.tools import (
    WebAppScannerToolkit,
)

logger = structlog.get_logger()


class WebAppScannerRunner:
    """Runner for the Web App Scanner Agent."""

    def __init__(
        self,
        http_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = WebAppScannerToolkit(
            http_client=http_client,
            policy_engine=policy_engine,
            repository=repository,
        )
        graph = build_graph(self._toolkit)
        self._app = graph.compile()
        self._results: dict[str, WebAppScannerState] = {}
        logger.info("web_app_scanner_runner.initialized")

    async def scan(
        self,
        tenant_id: str,
        target_url: str,
        auth_config: dict[str, Any] | None = None,
        scan_depth: int = 3,
    ) -> WebAppScannerState:
        """Run a web application scan."""
        session_id = f"was-{uuid4().hex[:12]}"

        initial = WebAppScannerState(
            request_id=session_id,
            tenant_id=tenant_id,
            target_url=target_url,
            auth_config=auth_config or {},
            scan_depth=scan_depth,
        )

        logger.info(
            "web_app_scanner_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            target=target_url,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "web_app_scanner",
                    }
                },
            )
            final = WebAppScannerState.model_validate(result)
            self._results[session_id] = final
            logger.info(
                "web_app_scanner_runner.completed",
                session_id=session_id,
                score=final.security_score,
                endpoints=len(final.endpoints_discovered),
            )
            return final

        except Exception as e:
            logger.error(
                "web_app_scanner_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            err = WebAppScannerState(
                request_id=session_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            self._results[session_id] = err
            return err

    def get_result(self, session_id: str) -> WebAppScannerState | None:
        """Get a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "target": s.target_url,
                "score": s.security_score,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

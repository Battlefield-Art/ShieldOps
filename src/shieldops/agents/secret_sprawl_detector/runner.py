"""Secret Sprawl Detector Agent runner — entry point
for secret and credential sprawl detection."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.secret_sprawl_detector.graph import (
    create_secret_sprawl_detector_graph,
)
from shieldops.agents.secret_sprawl_detector.models import (
    SecretSprawlDetectorState,
)
from shieldops.agents.secret_sprawl_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.secret_sprawl_detector.tools import (
    SecretSprawlDetectorToolkit,
)

logger = structlog.get_logger()


class SecretSprawlDetectorRunner:
    """Runner for the Secret Sprawl Detector Agent."""

    def __init__(
        self,
        git_client: Any | None = None,
        config_store: Any | None = None,
        secret_scanner: Any | None = None,
        risk_engine: Any | None = None,
        notification_service: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecretSprawlDetectorToolkit(
            git_client=git_client,
            config_store=config_store,
            secret_scanner=secret_scanner,
            risk_engine=risk_engine,
            notification_service=notification_service,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_secret_sprawl_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, SecretSprawlDetectorState] = {}
        logger.info("ssd_runner.initialized")

    async def detect(
        self,
        scan_name: str,
        target_repos: list[str] | None = None,
        target_configs: list[str] | None = None,
        scan_git_history: bool = True,
        entropy_threshold: float = 4.5,
        tenant_id: str = "",
    ) -> SecretSprawlDetectorState:
        """Run a secret sprawl detection scan."""
        request_id = f"ssd-{uuid4().hex[:12]}"

        initial_state = SecretSprawlDetectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            target_repos=target_repos or [],
            target_configs=target_configs or [],
            scan_git_history=scan_git_history,
            entropy_threshold=entropy_threshold,
        )

        logger.info(
            "ssd_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            repos=len(initial_state.target_repos),
            configs=len(initial_state.target_configs),
            scan_history=scan_git_history,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("secret_sprawl_detector"),
                    },
                },
            )
            final = SecretSprawlDetectorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "ssd_runner.completed",
                request_id=request_id,
                total_secrets=final.total_secrets,
                critical=final.critical_secrets,
                repos=final.repos_scanned,
                configs=final.configs_scanned,
                alerts=final.alerts_sent,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ssd_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecretSprawlDetectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_name=scan_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecretSprawlDetectorState | None:
        """Retrieve a cached scan result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_secrets": s.total_secrets,
                "critical": s.critical_secrets,
                "repos_scanned": s.repos_scanned,
                "configs_scanned": s.configs_scanned,
                "alerts_sent": s.alerts_sent,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

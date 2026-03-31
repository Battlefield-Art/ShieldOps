"""Access Certification Engine Agent runner — entry
point for executing access review campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.access_certification_engine.graph import (
    create_access_certification_engine_graph,
)
from shieldops.agents.access_certification_engine.models import (
    AccessCertificationEngineState,
)
from shieldops.agents.access_certification_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.access_certification_engine.tools import (
    AccessCertificationEngineToolkit,
)

logger = structlog.get_logger()


class AccessCertificationEngineRunner:
    """Runner for the Access Certification Engine Agent."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        hr_system: Any | None = None,
        usage_tracker: Any | None = None,
        sod_checker: Any | None = None,
        review_platform: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AccessCertificationEngineToolkit(
            identity_provider=identity_provider,
            hr_system=hr_system,
            usage_tracker=usage_tracker,
            sod_checker=sod_checker,
            review_platform=review_platform,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_access_certification_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, AccessCertificationEngineState] = {}
        logger.info("ace_runner.initialized")

    async def certify(
        self,
        campaign_name: str,
        identity_sources: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        review_period_days: int = 90,
        tenant_id: str = "",
    ) -> AccessCertificationEngineState:
        """Run an access certification campaign."""
        request_id = f"ace-{uuid4().hex[:12]}"

        initial_state = AccessCertificationEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            campaign_name=campaign_name,
            identity_sources=identity_sources or [],
            scope=scope or {},
            review_period_days=review_period_days,
        )

        logger.info(
            "ace_runner.starting",
            request_id=request_id,
            campaign=campaign_name,
            sources=len(identity_sources or []),
            period=review_period_days,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("access_certification_engine"),
                    },
                },
            )
            final = AccessCertificationEngineState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "ace_runner.completed",
                request_id=request_id,
                entitlements=final.total_entitlements,
                excess=final.excess_found,
                revocations=final.revocations_recommended,
                sod=final.sod_violations,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ace_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AccessCertificationEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                campaign_name=campaign_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> AccessCertificationEngineState | None:
        """Retrieve a cached certification result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all certification results as summaries."""
        return [
            {
                "request_id": rid,
                "campaign": s.campaign_name,
                "entitlements": s.total_entitlements,
                "excess": s.excess_found,
                "revocations": s.revocations_recommended,
                "sod_violations": s.sod_violations,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

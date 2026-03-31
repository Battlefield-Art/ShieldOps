"""Service Account Guardian Agent runner — entry point
for service account security audits."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.service_account_guardian.graph import (
    create_service_account_guardian_graph,
)
from shieldops.agents.service_account_guardian.models import (
    ServiceAccountGuardianState,
)
from shieldops.agents.service_account_guardian.nodes import (
    set_toolkit,
)
from shieldops.agents.service_account_guardian.tools import (
    ServiceAccountGuardianToolkit,
)

logger = structlog.get_logger()


class ServiceAccountGuardianRunner:
    """Runner for the Service Account Guardian Agent."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        permission_analyzer: Any | None = None,
        orphan_detector: Any | None = None,
        risk_engine: Any | None = None,
        remediation_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ServiceAccountGuardianToolkit(
            identity_provider=identity_provider,
            permission_analyzer=permission_analyzer,
            orphan_detector=orphan_detector,
            risk_engine=risk_engine,
            remediation_engine=remediation_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_service_account_guardian_graph()
        self._app = graph.compile()
        self._results: dict[str, ServiceAccountGuardianState] = {}
        logger.info("sag_runner.initialized")

    async def run_audit(
        self,
        scan_name: str,
        target_providers: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        auto_remediate: bool = False,
        tenant_id: str = "",
    ) -> ServiceAccountGuardianState:
        """Run a service account security audit."""
        request_id = f"sag-{uuid4().hex[:12]}"

        initial_state = ServiceAccountGuardianState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            target_providers=target_providers or [],
            scope=scope or {},
            auto_remediate=auto_remediate,
        )

        logger.info(
            "sag_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            providers=len(target_providers or []),
            auto_remediate=auto_remediate,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "service_account_guardian",
                    },
                },
            )
            final = ServiceAccountGuardianState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "sag_runner.completed",
                request_id=request_id,
                total_accounts=final.total_accounts,
                orphans=final.orphan_count,
                high_risk=final.high_risk_count,
                remediated=final.remediated_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sag_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ServiceAccountGuardianState(
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
    ) -> ServiceAccountGuardianState | None:
        """Retrieve a cached audit result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all audit results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_accounts": s.total_accounts,
                "orphans": s.orphan_count,
                "high_risk": s.high_risk_count,
                "remediated": s.remediated_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

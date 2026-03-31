"""Cloud Database Protector Agent runner — entry point
for database security and access monitoring."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_database_protector.graph import (
    create_cloud_database_protector_graph,
)
from shieldops.agents.cloud_database_protector.models import (
    CloudDatabaseProtectorState,
)
from shieldops.agents.cloud_database_protector.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_database_protector.tools import (
    CloudDatabaseProtectorToolkit,
)

logger = structlog.get_logger()


class CloudDatabaseProtectorRunner:
    """Runner for the Cloud Database Protector Agent."""

    def __init__(
        self,
        db_discovery: Any | None = None,
        access_auditor: Any | None = None,
        encryption_checker: Any | None = None,
        anomaly_detector: Any | None = None,
        policy_enforcer: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudDatabaseProtectorToolkit(
            db_discovery=db_discovery,
            access_auditor=access_auditor,
            encryption_checker=encryption_checker,
            anomaly_detector=anomaly_detector,
            policy_enforcer=policy_enforcer,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_database_protector_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudDatabaseProtectorState] = {}
        logger.info("cdp_runner.initialized")

    async def protect(
        self,
        providers: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        enforce_mode: bool = False,
        tenant_id: str = "",
    ) -> CloudDatabaseProtectorState:
        """Run database protection assessment."""
        request_id = f"cdp-{uuid4().hex[:12]}"

        initial_state = CloudDatabaseProtectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers or [],
            scope=scope or {},
            enforce_mode=enforce_mode,
        )

        logger.info(
            "cdp_runner.starting",
            request_id=request_id,
            providers=len(providers or []),
            enforce_mode=enforce_mode,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_database_protector",
                    },
                },
            )
            final = CloudDatabaseProtectorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cdp_runner.completed",
                request_id=request_id,
                total=final.total_databases,
                at_risk=final.at_risk_count,
                anomalies=final.anomaly_count,
                enforced=final.enforced_count,
            )
            return final

        except Exception as e:
            logger.error(
                "cdp_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudDatabaseProtectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CloudDatabaseProtectorState | None:
        """Retrieve a cached protection result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all protection results as summaries."""
        return [
            {
                "request_id": rid,
                "total_databases": s.total_databases,
                "at_risk_count": s.at_risk_count,
                "anomaly_count": s.anomaly_count,
                "enforced_count": s.enforced_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

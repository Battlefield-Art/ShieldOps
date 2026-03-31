"""ML Model Scanner Agent runner — entry point for
executing model supply chain security scans."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ml_model_scanner.graph import (
    create_ml_model_scanner_graph,
)
from shieldops.agents.ml_model_scanner.models import (
    MLModelScannerState,
)
from shieldops.agents.ml_model_scanner.nodes import (
    set_toolkit,
)
from shieldops.agents.ml_model_scanner.tools import (
    MLModelScannerToolkit,
)

logger = structlog.get_logger()


class MLModelScannerRunner:
    """Runner for the ML Model Scanner Agent."""

    def __init__(
        self,
        registry_client: Any | None = None,
        artifact_store: Any | None = None,
        provenance_service: Any | None = None,
        backdoor_detector: Any | None = None,
        risk_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MLModelScannerToolkit(
            registry_client=registry_client,
            artifact_store=artifact_store,
            provenance_service=provenance_service,
            backdoor_detector=backdoor_detector,
            risk_engine=risk_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_ml_model_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, MLModelScannerState] = {}
        logger.info("mms_runner.initialized")

    async def scan(
        self,
        scan_name: str,
        registries: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        formats_filter: list[str] | None = None,
        tenant_id: str = "",
    ) -> MLModelScannerState:
        """Run an ML model security scan."""
        request_id = f"mms-{uuid4().hex[:12]}"

        initial_state = MLModelScannerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            registries=registries or [],
            scope=scope or {},
            formats_filter=formats_filter or [],
        )

        logger.info(
            "mms_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            registries=len(registries or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "ml_model_scanner",
                    },
                },
            )
            final = MLModelScannerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "mms_runner.completed",
                request_id=request_id,
                total_models=final.total_models,
                vulnerable=final.vulnerable_models,
                critical=final.critical_count,
                risk_score=final.overall_risk_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "mms_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = MLModelScannerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_name=scan_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> MLModelScannerState | None:
        """Retrieve a cached scan result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_models": s.total_models,
                "vulnerable": s.vulnerable_models,
                "critical": s.critical_count,
                "risk_score": s.overall_risk_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

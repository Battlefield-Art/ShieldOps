"""Toxic Combination Detector Agent runner — entry point
for detecting toxic permission combinations."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.toxic_combination_detector.graph import (
    create_toxic_combination_detector_graph,
)
from shieldops.agents.toxic_combination_detector.models import (
    ToxicCombinationDetectorState,
)
from shieldops.agents.toxic_combination_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.toxic_combination_detector.tools import (
    ToxicCombinationDetectorToolkit,
)

logger = structlog.get_logger()


class ToxicCombinationDetectorRunner:
    """Runner for the Toxic Combination Detector Agent."""

    def __init__(
        self,
        iam_client: Any | None = None,
        permission_analyzer: Any | None = None,
        sod_engine: Any | None = None,
        blast_analyzer: Any | None = None,
        risk_scorer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ToxicCombinationDetectorToolkit(
            iam_client=iam_client,
            permission_analyzer=permission_analyzer,
            sod_engine=sod_engine,
            blast_analyzer=blast_analyzer,
            risk_scorer=risk_scorer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_toxic_combination_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, ToxicCombinationDetectorState] = {}
        logger.info("tcd_runner.initialized")

    async def detect(
        self,
        scan_name: str,
        target_providers: list[str] | None = None,
        target_identities: list[str] | None = None,
        sod_policies: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> ToxicCombinationDetectorState:
        """Run a toxic permission combination detection scan."""
        request_id = f"tcd-{uuid4().hex[:12]}"

        initial_state = ToxicCombinationDetectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            target_providers=target_providers or [],
            target_identities=target_identities or [],
            sod_policies=sod_policies or {},
        )

        logger.info(
            "tcd_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            providers=len(initial_state.target_providers),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("toxic_combination_detector"),
                    },
                },
            )
            final = ToxicCombinationDetectorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "tcd_runner.completed",
                request_id=request_id,
                total_identities=final.total_identities,
                total_toxic=final.total_toxic,
                critical=final.critical_toxic,
                max_blast=final.max_blast_radius,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tcd_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ToxicCombinationDetectorState(
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
    ) -> ToxicCombinationDetectorState | None:
        """Retrieve a cached detection result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all detection results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_identities": s.total_identities,
                "total_toxic": s.total_toxic,
                "critical": s.critical_toxic,
                "max_blast_radius": s.max_blast_radius,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

"""Exposure Management Agent runner — entry point for
executing exposure management assessment workflows.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.exposure_management.graph import (
    create_exposure_management_graph,
)
from shieldops.agents.exposure_management.models import (
    ExposureManagementState,
)
from shieldops.agents.exposure_management.nodes import (
    set_toolkit,
)
from shieldops.agents.exposure_management.tools import (
    ExposureManagementToolkit,
)

logger = structlog.get_logger()


class ExposureManagementRunner:
    """Runner for the Exposure Management Agent."""

    def __init__(
        self,
        surface_scanner: Any | None = None,
        asset_enumerator: Any | None = None,
        exposure_assessor: Any | None = None,
        risk_prioritizer: Any | None = None,
        remediation_engine: Any | None = None,
        ai_surface_scanner: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ExposureManagementToolkit(
            surface_scanner=surface_scanner,
            asset_enumerator=asset_enumerator,
            exposure_assessor=exposure_assessor,
            risk_prioritizer=risk_prioritizer,
            remediation_engine=remediation_engine,
            ai_surface_scanner=ai_surface_scanner,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_exposure_management_graph()
        self._app = graph.compile()
        self._results: dict[str, ExposureManagementState] = {}
        logger.info("exposure_management_runner.initialized")

    async def assess(
        self,
        tenant_id: str,
        assessment_id: str | None = None,
        scan_config: dict[str, Any] | None = None,
    ) -> ExposureManagementState:
        """Run exposure management assessment workflow.

        Args:
            tenant_id: Tenant identifier.
            assessment_id: Optional assessment ID.
            scan_config: Optional scan configuration
                with scope, surface_types, and
                business_context.

        Returns:
            Final ExposureManagementState with all
            discovered surfaces, assets, exposures,
            priorities, and recommendations.
        """
        session_id = f"em-{uuid4().hex[:12]}"
        aid = assessment_id or f"ea-{uuid4().hex[:8]}"
        initial_state = ExposureManagementState(
            tenant_id=tenant_id,
            assessment_id=aid,
            scan_config=scan_config or {},
        )

        logger.info(
            "exposure_management_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            assessment_id=aid,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "exposure_management",
                    },
                },
            )
            final_state = ExposureManagementState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "exposure_management_runner.completed",
                session_id=session_id,
                surface_count=final_state.surface_count,
                asset_count=final_state.asset_count,
                critical_count=(final_state.critical_count),
                ai_exposures=(final_state.ai_exposure_count),
                total_score=(final_state.total_exposure_score),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "exposure_management_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = ExposureManagementState(
                tenant_id=tenant_id,
                assessment_id=aid,
                scan_config=scan_config or {},
                error=str(e),
                current_stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> ExposureManagementState | None:
        """Retrieve a previous assessment result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all assessment results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "assessment_id": state.assessment_id,
                "surface_count": state.surface_count,
                "asset_count": state.asset_count,
                "critical_count": state.critical_count,
                "ai_exposure_count": (state.ai_exposure_count),
                "total_exposure_score": (state.total_exposure_score),
                "current_stage": state.current_stage,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

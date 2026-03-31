"""Privacy Rights Automator Agent runner — entry point
for executing DSAR/CCPA/GDPR request automation."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.privacy_rights_automator.graph import (
    create_privacy_rights_automator_graph,
)
from shieldops.agents.privacy_rights_automator.models import (
    PrivacyRightsAutomatorState,
    RegulationFramework,
    RequestType,
)
from shieldops.agents.privacy_rights_automator.nodes import (
    set_toolkit,
)
from shieldops.agents.privacy_rights_automator.tools import (
    PrivacyRightsAutomatorToolkit,
)

logger = structlog.get_logger()


class PrivacyRightsAutomatorRunner:
    """Runner for the Privacy Rights Automator Agent."""

    def __init__(
        self,
        data_catalog: Any | None = None,
        pii_classifier: Any | None = None,
        action_processor: Any | None = None,
        verification_engine: Any | None = None,
        compliance_store: Any | None = None,
        metrics_tracker: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PrivacyRightsAutomatorToolkit(
            data_catalog=data_catalog,
            pii_classifier=pii_classifier,
            action_processor=action_processor,
            verification_engine=verification_engine,
            compliance_store=compliance_store,
            metrics_tracker=metrics_tracker,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_privacy_rights_automator_graph()
        self._app = graph.compile()
        self._results: dict[str, PrivacyRightsAutomatorState] = {}
        logger.info("pra_runner.initialized")

    async def process_request(
        self,
        subject_email: str,
        request_type: str = "access",
        regulation: str = "gdpr",
        systems: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> PrivacyRightsAutomatorState:
        """Process a data subject rights request."""
        request_id = f"pra-{uuid4().hex[:12]}"

        initial_state = PrivacyRightsAutomatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            subject_email=subject_email,
            request_type=RequestType(request_type),
            regulation=RegulationFramework(regulation),
            systems=systems or [],
            scope=scope or {},
        )

        logger.info(
            "pra_runner.starting",
            request_id=request_id,
            subject=subject_email,
            request_type=request_type,
            regulation=regulation,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("privacy_rights_automator"),
                    },
                },
            )
            final = PrivacyRightsAutomatorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "pra_runner.completed",
                request_id=request_id,
                fulfilled=final.request_fulfilled,
                total_records=final.total_records,
                systems=final.systems_processed,
                compliance=final.compliance_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "pra_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = PrivacyRightsAutomatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                subject_email=subject_email,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> PrivacyRightsAutomatorState | None:
        """Retrieve a cached request result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all request results as summaries."""
        return [
            {
                "request_id": rid,
                "subject": s.subject_email,
                "request_type": s.request_type.value,
                "regulation": s.regulation.value,
                "fulfilled": s.request_fulfilled,
                "total_records": s.total_records,
                "systems_processed": s.systems_processed,
                "compliance": s.compliance_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

"""Access Review Agent runner — entry point for access review campaigns."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.access_review.graph import create_access_review_graph
from shieldops.agents.access_review.models import AccessReviewState
from shieldops.agents.access_review.nodes import set_toolkit
from shieldops.agents.access_review.tools import AccessReviewToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.observability.tracing import get_tracer

if __import__("typing").TYPE_CHECKING:
    from shieldops.db.repository import Repository

logger = structlog.get_logger()


class AccessReviewRunner:
    """Runs access review campaign workflows.

    Usage:
        runner = AccessReviewRunner(connector_router=router)
        result = await runner.run_campaign(
            tenant_id="tenant-acme",
            campaign_name="Q1-2026 Access Review",
        )
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: "Repository | None" = None,
    ) -> None:
        self._toolkit = AccessReviewToolkit(
            connector_router=connector_router,
            repository=repository,
        )
        set_toolkit(self._toolkit)

        graph = create_access_review_graph()
        self._app = graph.compile()

        self._campaigns: dict[str, AccessReviewState] = {}
        self._repository = repository

    async def run_campaign(
        self,
        tenant_id: str,
        campaign_name: str,
        context: dict[str, Any] | None = None,
    ) -> AccessReviewState:
        """Run a full access review campaign for a tenant.

        Args:
            tenant_id: The tenant/org to run the campaign for.
            campaign_name: Human-readable campaign name (e.g. "Q1-2026").
            context: Additional context (filters, scope, etc.).

        Returns:
            The completed AccessReviewState with findings and certifications.
        """
        campaign_id = f"ar-{uuid4().hex[:12]}"
        context = context or {}

        logger.info(
            "access_review_campaign_started",
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            campaign_name=campaign_name,
        )

        initial_state = AccessReviewState(
            request_id=campaign_id,
            tenant_id=tenant_id,
            campaign_name=campaign_name,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("access_review.campaign") as span:
                span.set_attribute("access_review.campaign_id", campaign_id)
                span.set_attribute("access_review.tenant_id", tenant_id)
                span.set_attribute("access_review.campaign_name", campaign_name)

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "campaign_id": campaign_id,
                            "tenant_id": tenant_id,
                            "campaign_name": campaign_name,
                        },
                    },
                )

                final_state = AccessReviewState.model_validate(final_state_dict)

                span.set_attribute(
                    "access_review.entitlements",
                    len(final_state.entitlements),
                )
                span.set_attribute(
                    "access_review.violations",
                    len(final_state.violations),
                )
                span.set_attribute(
                    "access_review.certifications",
                    len(final_state.certifications),
                )

            logger.info(
                "access_review_campaign_completed",
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                campaign_name=campaign_name,
                entitlements=len(final_state.entitlements),
                violations=len(final_state.violations),
                tasks=len(final_state.review_tasks),
                certifications=len(final_state.certifications),
                duration_ms=final_state.session_duration_ms,
            )

            self._campaigns[campaign_id] = final_state
            return final_state

        except Exception as exc:
            logger.error(
                "access_review_campaign_failed",
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                error=str(exc),
            )
            error_state = AccessReviewState(
                request_id=campaign_id,
                tenant_id=tenant_id,
                campaign_name=campaign_name,
                error=str(exc),
                current_step="failed",
            )
            self._campaigns[campaign_id] = error_state
            return error_state

    def get_campaign(self, campaign_id: str) -> AccessReviewState | None:
        """Retrieve a completed campaign by ID."""
        return self._campaigns.get(campaign_id)

    def list_campaigns(self) -> list[dict[str, Any]]:
        """List all campaigns with summary info."""
        return [
            {
                "campaign_id": cid,
                "tenant_id": state.tenant_id,
                "campaign_name": state.campaign_name,
                "status": state.current_step,
                "entitlements": len(state.entitlements),
                "violations": len(state.violations),
                "tasks": len(state.review_tasks),
                "certifications": len(state.certifications),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for cid, state in self._campaigns.items()
        ]

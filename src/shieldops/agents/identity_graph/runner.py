"""Identity Graph Agent runner — entry point for identity graph scanning."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.identity_graph.graph import create_identity_graph
from shieldops.agents.identity_graph.models import IdentityGraphState
from shieldops.agents.identity_graph.nodes import set_toolkit
from shieldops.agents.identity_graph.tools import IdentityGraphToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.observability.tracing import get_tracer

if __import__("typing").TYPE_CHECKING:
    from shieldops.db.repository import Repository

logger = structlog.get_logger()


class IdentityGraphRunner:
    """Runs identity graph scanning workflows.

    Usage:
        runner = IdentityGraphRunner(connector_router=router)
        result = await runner.scan("org-acme", context={"scope": "production"})
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: "Repository | None" = None,
    ) -> None:
        self._toolkit = IdentityGraphToolkit(
            connector_router=connector_router,
            repository=repository,
        )
        set_toolkit(self._toolkit)

        graph = create_identity_graph()
        self._app = graph.compile()

        self._scans: dict[str, IdentityGraphState] = {}
        self._repository = repository

    async def scan(
        self,
        target: str,
        context: dict[str, Any] | None = None,
    ) -> IdentityGraphState:
        """Run a full identity graph scan for a target org/tenant.

        Args:
            target: The org, tenant, or domain to scan.
            context: Additional context (scope, identity_types, etc.).

        Returns:
            The completed IdentityGraphState with findings and remediations.
        """
        scan_id = f"igscan-{uuid4().hex[:12]}"
        context = context or {}

        logger.info(
            "identity_graph_scan_started",
            scan_id=scan_id,
            target=target,
        )

        initial_state = IdentityGraphState(
            scan_target=target,
            identity_types=context.get("identity_types", ["human", "service_account", "ai_agent"]),
            scope=context.get("scope", {}),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("identity_graph.scan") as span:
                span.set_attribute("identity_graph.scan_id", scan_id)
                span.set_attribute("identity_graph.target", target)

                final_state_dict = await self._app.ainvoke(  # type: ignore[arg-type]
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "scan_id": scan_id,
                            "target": target,
                        },
                    },
                )

                final_state = IdentityGraphState.model_validate(final_state_dict)

                span.set_attribute(
                    "identity_graph.identities_found",
                    len(final_state.identities_discovered),
                )
                span.set_attribute(
                    "identity_graph.risks_found",
                    len(final_state.risk_assessments),
                )

            logger.info(
                "identity_graph_scan_completed",
                scan_id=scan_id,
                target=target,
                identities=len(final_state.identities_discovered),
                relationships=len(final_state.relationships_mapped),
                risks=len(final_state.risk_assessments),
                remediations=len(final_state.remediation_actions),
                duration_ms=final_state.session_duration_ms,
            )

            self._scans[scan_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "identity_graph_scan_failed",
                scan_id=scan_id,
                target=target,
                error=str(e),
            )
            error_state = IdentityGraphState(
                scan_target=target,
                error=str(e),
                current_step="failed",
            )
            self._scans[scan_id] = error_state
            return error_state

    def get_scan(self, scan_id: str) -> IdentityGraphState | None:
        """Retrieve a completed scan by ID."""
        return self._scans.get(scan_id)

    def list_scans(self) -> list[dict[str, Any]]:
        """List all scans with summary info."""
        return [
            {
                "scan_id": sid,
                "target": state.scan_target,
                "status": state.current_step,
                "identities": len(state.identities_discovered),
                "risks": len(state.risk_assessments),
                "remediations": len(state.remediation_actions),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for sid, state in self._scans.items()
        ]

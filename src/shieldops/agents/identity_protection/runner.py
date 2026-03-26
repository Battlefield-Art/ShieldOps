"""Identity Protection Agent runner — entry point."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.identity_protection.graph import (
    create_identity_protection_graph,
)
from shieldops.agents.identity_protection.models import (
    IdentityProtectionState,
)
from shieldops.agents.identity_protection.nodes import (
    set_toolkit,
)
from shieldops.agents.identity_protection.tools import (
    IdentityProtectionToolkit,
)
from shieldops.connectors.base import ConnectorRouter
from shieldops.observability.tracing import get_tracer

if __import__("typing").TYPE_CHECKING:
    from shieldops.db.repository import Repository

logger = structlog.get_logger()


class IdentityProtectionRunner:
    """Runs identity protection workflows.

    Usage:
        runner = IdentityProtectionRunner(
            connector_router=router,
        )
        result = await runner.protect(
            "tenant-acme",
            context={"providers": ["okta", "entra_id"]},
        )
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: "Repository | None" = None,
    ) -> None:
        self._toolkit = IdentityProtectionToolkit(
            connector_router=connector_router,
            repository=repository,
        )
        set_toolkit(self._toolkit)

        graph = create_identity_protection_graph()
        self._app = graph.compile()

        self._runs: dict[str, IdentityProtectionState] = {}
        self._repository = repository

    async def protect(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> IdentityProtectionState:
        """Run identity protection for a tenant.

        Args:
            tenant_id: The tenant/org to protect.
            context: Additional context (providers, etc).

        Returns:
            Completed IdentityProtectionState.
        """
        run_id = f"idp-{uuid4().hex[:12]}"
        context = context or {}

        logger.info(
            "identity_protection_started",
            run_id=run_id,
            tenant_id=tenant_id,
        )

        default_providers = [
            "okta",
            "entra_id",
            "aws_iam",
            "gcp_iam",
            "k8s_rbac",
            "ai_agent_registry",
        ]

        initial_state = IdentityProtectionState(
            tenant_id=tenant_id,
            providers=context.get(
                "providers",
                default_providers,
            ),
            time_window_minutes=context.get(
                "time_window_minutes",
                60,
            ),
            scope=context.get("scope", {}),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span(
                "identity_protection.protect",
            ) as span:
                span.set_attribute(
                    "identity_protection.run_id",
                    run_id,
                )
                span.set_attribute(
                    "identity_protection.tenant_id",
                    tenant_id,
                )

                final_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "run_id": run_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final_state = IdentityProtectionState.model_validate(
                    final_dict,
                )

                span.set_attribute(
                    "identity_protection.signals",
                    len(final_state.signals_collected),
                )
                span.set_attribute(
                    "identity_protection.threats",
                    len(final_state.threats_detected),
                )
                span.set_attribute(
                    "identity_protection.responses",
                    len(final_state.responses_executed),
                )

            logger.info(
                "identity_protection_completed",
                run_id=run_id,
                tenant_id=tenant_id,
                signals=len(
                    final_state.signals_collected,
                ),
                threats=len(
                    final_state.threats_detected,
                ),
                patterns=len(
                    final_state.attack_patterns,
                ),
                responses=len(
                    final_state.responses_executed,
                ),
                contained=sum(1 for v in (final_state.containment_verified) if v.is_contained),
                duration_ms=(final_state.session_duration_ms),
            )

            self._runs[run_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "identity_protection_failed",
                run_id=run_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            error_state = IdentityProtectionState(
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[run_id] = error_state
            return error_state

    def get_run(
        self,
        run_id: str,
    ) -> IdentityProtectionState | None:
        """Retrieve a completed run by ID."""
        return self._runs.get(run_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "run_id": rid,
                "tenant_id": state.tenant_id,
                "status": state.current_step,
                "signals": len(
                    state.signals_collected,
                ),
                "threats": len(
                    state.threats_detected,
                ),
                "responses": len(
                    state.responses_executed,
                ),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._runs.items()
        ]

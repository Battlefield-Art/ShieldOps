"""Policy Compliance Enforcer Agent runner — entry point
for real-time policy enforcement and compliance gating."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.policy_compliance_enforcer.graph import (
    create_policy_compliance_enforcer_graph,
)
from shieldops.agents.policy_compliance_enforcer.models import (
    PolicyComplianceEnforcerState,
)
from shieldops.agents.policy_compliance_enforcer.nodes import (
    set_toolkit,
)
from shieldops.agents.policy_compliance_enforcer.tools import (
    PolicyComplianceEnforcerToolkit,
)

logger = structlog.get_logger()


class PolicyComplianceEnforcerRunner:
    """Runner for the Policy Compliance Enforcer Agent."""

    def __init__(
        self,
        opa_client: Any | None = None,
        compliance_store: Any | None = None,
        exemption_registry: Any | None = None,
        audit_store: Any | None = None,
        notification_service: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PolicyComplianceEnforcerToolkit(
            opa_client=opa_client,
            compliance_store=compliance_store,
            exemption_registry=exemption_registry,
            audit_store=audit_store,
            notification_service=notification_service,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_policy_compliance_enforcer_graph()
        self._app = graph.compile()
        self._results: dict[str, PolicyComplianceEnforcerState] = {}
        logger.info("pce_runner.initialized")

    async def enforce(
        self,
        request_type: str,
        resource: str,
        actor: str = "",
        context: dict[str, Any] | None = None,
        frameworks: list[str] | None = None,
        tenant_id: str = "",
    ) -> PolicyComplianceEnforcerState:
        """Enforce policies on a request."""
        request_id = f"pce-{uuid4().hex[:12]}"

        initial_state = PolicyComplianceEnforcerState(
            request_id=request_id,
            tenant_id=tenant_id,
            request_type=request_type,
            resource=resource,
            actor=actor,
            context=context or {},
            frameworks=frameworks or [],
        )

        logger.info(
            "pce_runner.starting",
            request_id=request_id,
            request_type=request_type,
            resource=resource,
            actor=actor,
            frameworks=len(initial_state.frameworks),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("policy_compliance_enforcer"),
                    },
                },
            )
            final = PolicyComplianceEnforcerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "pce_runner.completed",
                request_id=request_id,
                action=final.enforcement_action,
                violations=final.violation_count,
                compliant=final.compliant,
                exemptions=final.exemptions_applied,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "pce_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = PolicyComplianceEnforcerState(
                request_id=request_id,
                tenant_id=tenant_id,
                request_type=request_type,
                resource=resource,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> PolicyComplianceEnforcerState | None:
        """Retrieve a cached enforcement result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all enforcement results as summaries."""
        return [
            {
                "request_id": rid,
                "resource": s.resource,
                "action": s.enforcement_action,
                "violations": s.violation_count,
                "compliant": s.compliant,
                "exemptions": s.exemptions_applied,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

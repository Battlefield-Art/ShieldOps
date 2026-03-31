"""Security Onboarding Engine Agent runner — entry point
for executing automated service onboarding."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_onboarding_engine.graph import (
    create_security_onboarding_engine_graph,
)
from shieldops.agents.security_onboarding_engine.models import (
    DataClassification,
    SecurityOnboardingEngineState,
    ServiceTier,
)
from shieldops.agents.security_onboarding_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.security_onboarding_engine.tools import (
    SecurityOnboardingEngineToolkit,
)

logger = structlog.get_logger()


class SecurityOnboardingEngineRunner:
    """Runner for the Security Onboarding Engine Agent."""

    def __init__(
        self,
        risk_assessor: Any | None = None,
        requirement_engine: Any | None = None,
        control_provisioner: Any | None = None,
        validator: Any | None = None,
        compliance_mapper: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityOnboardingEngineToolkit(
            risk_assessor=risk_assessor,
            requirement_engine=requirement_engine,
            control_provisioner=control_provisioner,
            validator=validator,
            compliance_mapper=compliance_mapper,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_onboarding_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityOnboardingEngineState] = {}
        logger.info("soe_runner.initialized")

    async def onboard(
        self,
        service_name: str,
        team: str,
        owner: str,
        environment: str = "production",
        tier: str = "standard",
        data_classification: str = "internal",
        tech_stack: list[str] | None = None,
        external_facing: bool = False,
        tenant_id: str = "",
    ) -> SecurityOnboardingEngineState:
        """Run automated security onboarding for a service."""
        request_id = f"soe-{uuid4().hex[:12]}"

        initial_state = SecurityOnboardingEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            service_name=service_name,
            team=team,
            owner=owner,
            environment=environment,
            tier=ServiceTier(tier),
            data_classification=DataClassification(
                data_classification,
            ),
            tech_stack=tech_stack or [],
            external_facing=external_facing,
        )

        logger.info(
            "soe_runner.starting",
            request_id=request_id,
            service=service_name,
            tier=tier,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_onboarding_engine",
                    },
                },
            )
            final = SecurityOnboardingEngineState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "soe_runner.completed",
                request_id=request_id,
                service=service_name,
                requirements=final.total_requirements,
                controls=final.controls_provisioned,
                passed=final.controls_passed,
                complete=final.onboarding_complete,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "soe_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityOnboardingEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                service_name=service_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityOnboardingEngineState | None:
        """Retrieve a cached onboarding result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all onboarding results as summaries."""
        return [
            {
                "request_id": rid,
                "service": s.service_name,
                "tier": s.tier.value,
                "requirements": s.total_requirements,
                "controls": s.controls_provisioned,
                "passed": s.controls_passed,
                "complete": s.onboarding_complete,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

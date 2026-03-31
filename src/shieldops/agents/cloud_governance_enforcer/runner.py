"""Cloud Governance Enforcer Agent runner — entry point
for executing governance enforcement campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_governance_enforcer.graph import (
    create_cloud_governance_enforcer_graph,
)
from shieldops.agents.cloud_governance_enforcer.models import (
    CloudGovernanceEnforcerState,
)
from shieldops.agents.cloud_governance_enforcer.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_governance_enforcer.tools import (
    CloudGovernanceEnforcerToolkit,
)

logger = structlog.get_logger()


class CloudGovernanceEnforcerRunner:
    """Runner for the Cloud Governance Enforcer Agent."""

    def __init__(
        self,
        cloud_scanner: Any | None = None,
        tag_engine: Any | None = None,
        policy_evaluator: Any | None = None,
        violation_detector: Any | None = None,
        remediation_engine: Any | None = None,
        cost_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudGovernanceEnforcerToolkit(
            cloud_scanner=cloud_scanner,
            tag_engine=tag_engine,
            policy_evaluator=policy_evaluator,
            violation_detector=violation_detector,
            remediation_engine=remediation_engine,
            cost_engine=cost_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_governance_enforcer_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudGovernanceEnforcerState] = {}
        logger.info("cge_runner.initialized")

    async def enforce(
        self,
        scan_scope: str,
        cloud_providers: list[str] | None = None,
        required_tags: list[str] | None = None,
        auto_remediate: bool = False,
        tenant_id: str = "",
    ) -> CloudGovernanceEnforcerState:
        """Run a cloud governance enforcement campaign."""
        request_id = f"cge-{uuid4().hex[:12]}"

        initial_state = CloudGovernanceEnforcerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_scope=scan_scope,
            cloud_providers=cloud_providers or [],
            required_tags=required_tags or [],
            auto_remediate=auto_remediate,
        )

        logger.info(
            "cge_runner.starting",
            request_id=request_id,
            scope=scan_scope,
            providers=len(cloud_providers or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("cloud_governance_enforcer"),
                    },
                },
            )
            final = CloudGovernanceEnforcerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cge_runner.completed",
                request_id=request_id,
                total_resources=final.total_resources,
                compliant=final.compliant_resources,
                violations=final.total_violations,
                remediations=final.remediations_applied,
                score=final.compliance_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cge_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudGovernanceEnforcerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_scope=scan_scope,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CloudGovernanceEnforcerState | None:
        """Retrieve a cached enforcement result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all enforcement results as summaries."""
        return [
            {
                "request_id": rid,
                "scope": s.scan_scope,
                "total_resources": s.total_resources,
                "compliant": s.compliant_resources,
                "violations": s.total_violations,
                "remediations": s.remediations_applied,
                "compliance_score": s.compliance_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

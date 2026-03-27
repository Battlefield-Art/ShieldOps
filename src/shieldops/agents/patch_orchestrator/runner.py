"""Patch Orchestrator Agent runner — entry point."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.patch_orchestrator.graph import (
    build_graph,
)
from shieldops.agents.patch_orchestrator.models import (
    PatchOrchestratorState,
)
from shieldops.agents.patch_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.patch_orchestrator.tools import (
    PatchOrchestratorToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class PatchOrchestratorRunner:
    """Runs patch orchestration workflows."""

    def __init__(
        self,
        opa_client: Any = None,
        infra_client: Any = None,
    ) -> None:
        self._toolkit = PatchOrchestratorToolkit(
            opa_client=opa_client,
            infra_client=infra_client,
        )
        set_toolkit(self._toolkit)
        graph = build_graph()
        self._app = graph.compile()
        self._runs: dict[str, PatchOrchestratorState] = {}

    async def deploy(
        self,
        tenant_id: str,
        target_environment: str = "production",
    ) -> PatchOrchestratorState:
        """Run a full patch deployment workflow."""
        logger.info(
            "patch_deploy_started",
            tenant_id=tenant_id,
            environment=target_environment,
        )

        initial = PatchOrchestratorState(
            tenant_id=tenant_id,
            target_environment=target_environment,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("patch_orchestrator.deploy") as span:
                span.set_attribute("patch.tenant_id", tenant_id)
                span.set_attribute(
                    "patch.environment",
                    target_environment,
                )

                result = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = PatchOrchestratorState.model_validate(result)
                span.set_attribute("patch.patched", final.patched_count)
                span.set_attribute("patch.failed", final.failed_count)

            self._runs[final.request_id] = final
            logger.info(
                "patch_deploy_completed",
                tenant_id=tenant_id,
                patched=final.patched_count,
                failed=final.failed_count,
                rolled_back=final.rollback_count,
            )
            return final

        except Exception as e:
            logger.error(
                "patch_deploy_failed",
                tenant_id=tenant_id,
                error=str(e),
            )
            return PatchOrchestratorState(
                tenant_id=tenant_id,
                target_environment=target_environment,
                error=str(e),
                current_stage="failed",
            )

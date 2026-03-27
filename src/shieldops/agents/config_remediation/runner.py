"""Config Remediation Agent runner — entry point."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.config_remediation.graph import (
    build_graph,
)
from shieldops.agents.config_remediation.models import (
    ConfigRemediationState,
)
from shieldops.agents.config_remediation.nodes import (
    set_toolkit,
)
from shieldops.agents.config_remediation.tools import (
    ConfigRemediationToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class ConfigRemediationRunner:
    """Runs config remediation workflows."""

    def __init__(
        self,
        opa_client: Any = None,
        cloud_client: Any = None,
    ) -> None:
        self._toolkit = ConfigRemediationToolkit(
            opa_client=opa_client,
            cloud_client=cloud_client,
        )
        set_toolkit(self._toolkit)
        graph = build_graph()
        self._app = graph.compile()
        self._runs: dict[str, ConfigRemediationState] = {}

    async def remediate(
        self,
        tenant_id: str,
        target_cloud: str = "aws",
        dry_run: bool = True,
    ) -> ConfigRemediationState:
        """Run a full config remediation workflow."""
        logger.info(
            "config_remediation_started",
            tenant_id=tenant_id,
            cloud=target_cloud,
            dry_run=dry_run,
        )

        initial = ConfigRemediationState(
            tenant_id=tenant_id,
            target_cloud=target_cloud,
            dry_run=dry_run,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("config_remediation.remediate") as span:
                span.set_attribute("cfgrem.tenant_id", tenant_id)
                span.set_attribute("cfgrem.cloud", target_cloud)

                result = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = ConfigRemediationState.model_validate(result)
                span.set_attribute(
                    "cfgrem.auto_fixed",
                    final.auto_fixed_count,
                )

            self._runs[final.request_id] = final
            logger.info(
                "config_remediation_completed",
                tenant_id=tenant_id,
                auto_fixed=final.auto_fixed_count,
                manual=final.manual_required,
            )
            return final

        except Exception as e:
            logger.error(
                "config_remediation_failed",
                tenant_id=tenant_id,
                error=str(e),
            )
            return ConfigRemediationState(
                tenant_id=tenant_id,
                target_cloud=target_cloud,
                error=str(e),
                current_stage="failed",
            )

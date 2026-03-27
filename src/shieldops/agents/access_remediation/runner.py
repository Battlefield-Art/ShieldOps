"""Access Remediation Agent runner — entry point."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.access_remediation.graph import (
    build_graph,
)
from shieldops.agents.access_remediation.models import (
    AccessRemediationState,
)
from shieldops.agents.access_remediation.nodes import (
    set_toolkit,
)
from shieldops.agents.access_remediation.tools import (
    AccessRemediationToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AccessRemediationRunner:
    """Runs access remediation workflows."""

    def __init__(
        self,
        opa_client: Any = None,
        idp_client: Any = None,
    ) -> None:
        self._toolkit = AccessRemediationToolkit(
            opa_client=opa_client,
            idp_client=idp_client,
        )
        set_toolkit(self._toolkit)
        graph = build_graph()
        self._app = graph.compile()
        self._runs: dict[str, AccessRemediationState] = {}

    async def remediate(
        self,
        tenant_id: str,
        target_provider: str = "aws",
    ) -> AccessRemediationState:
        """Run a full access remediation workflow."""
        logger.info(
            "access_remediation_started",
            tenant_id=tenant_id,
            provider=target_provider,
        )

        initial = AccessRemediationState(
            tenant_id=tenant_id,
            target_provider=target_provider,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("access_remediation.remediate") as span:
                span.set_attribute("accrem.tenant_id", tenant_id)
                span.set_attribute("accrem.provider", target_provider)

                result = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = AccessRemediationState.model_validate(result)
                span.set_attribute(
                    "accrem.remediated",
                    final.accounts_remediated,
                )

            self._runs[final.request_id] = final
            logger.info(
                "access_remediation_completed",
                tenant_id=tenant_id,
                remediated=final.accounts_remediated,
            )
            return final

        except Exception as e:
            logger.error(
                "access_remediation_failed",
                tenant_id=tenant_id,
                error=str(e),
            )
            return AccessRemediationState(
                tenant_id=tenant_id,
                target_provider=target_provider,
                error=str(e),
                current_stage="failed",
            )

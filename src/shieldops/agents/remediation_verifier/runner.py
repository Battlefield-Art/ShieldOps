"""Remediation Verifier Agent runner — entry point."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.remediation_verifier.graph import (
    build_graph,
)
from shieldops.agents.remediation_verifier.models import (
    RemediationVerifierState,
)
from shieldops.agents.remediation_verifier.nodes import (
    set_toolkit,
)
from shieldops.agents.remediation_verifier.tools import (
    RemediationVerifierToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class RemediationVerifierRunner:
    """Runs remediation verification workflows."""

    def __init__(
        self,
        scanner_client: Any = None,
    ) -> None:
        self._toolkit = RemediationVerifierToolkit(
            scanner_client=scanner_client,
        )
        set_toolkit(self._toolkit)
        graph = build_graph()
        self._app = graph.compile()
        self._runs: dict[str, RemediationVerifierState] = {}

    async def verify(
        self,
        tenant_id: str,
    ) -> RemediationVerifierState:
        """Run a full remediation verification."""
        logger.info(
            "remediation_verify_started",
            tenant_id=tenant_id,
        )

        initial = RemediationVerifierState(
            tenant_id=tenant_id,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("remediation_verifier.verify") as span:
                span.set_attribute("remver.tenant_id", tenant_id)

                result = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = RemediationVerifierState.model_validate(result)
                span.set_attribute(
                    "remver.fixed",
                    final.verified_fixed_count,
                )
                span.set_attribute(
                    "remver.vulnerable",
                    final.still_vulnerable_count,
                )

            self._runs[final.request_id] = final
            logger.info(
                "remediation_verify_completed",
                tenant_id=tenant_id,
                fixed=final.verified_fixed_count,
                vulnerable=(final.still_vulnerable_count),
                regressions=(len(final.regressions_found)),
            )
            return final

        except Exception as e:
            logger.error(
                "remediation_verify_failed",
                tenant_id=tenant_id,
                error=str(e),
            )
            return RemediationVerifierState(
                tenant_id=tenant_id,
                error=str(e),
                current_stage="failed",
            )

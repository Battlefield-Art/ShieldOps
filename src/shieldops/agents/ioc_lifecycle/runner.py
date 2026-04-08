"""IOC Lifecycle Agent runner -- entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ioc_lifecycle.graph import (
    create_ioc_lifecycle_graph,
)
from shieldops.agents.ioc_lifecycle.models import (
    IOCLifecycleState,
)
from shieldops.agents.ioc_lifecycle.nodes import (
    set_toolkit,
)
from shieldops.agents.ioc_lifecycle.tools import (
    IOCLifecycleToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IOCLifecycleRunner:
    """Runner for the IOC Lifecycle Agent."""

    def __init__(
        self,
        threat_intel_client: Any | None = None,
        enrichment_client: Any | None = None,
    ) -> None:
        self._toolkit = IOCLifecycleToolkit(
            threat_intel_client=threat_intel_client,
            enrichment_client=enrichment_client,
        )
        set_toolkit(self._toolkit)
        graph = create_ioc_lifecycle_graph()
        self._app = graph.compile()
        self._results: dict[str, IOCLifecycleState] = {}
        logger.info("ioc_lifecycle_runner.initialized")

    @enforced("ioc_lifecycle")
    async def execute(
        self,
        tenant_id: str,
        sources: list[str] | None = None,
    ) -> IOCLifecycleState:
        """Run IOC lifecycle management.

        Args:
            tenant_id: Tenant identifier.
            sources: IOC sources to collect from.

        Returns:
            Final state with IOC lifecycle report.
        """
        session_id = f"ioc-lifecycle-{uuid4().hex[:12]}"
        initial_state = IOCLifecycleState(
            request_id=session_id,
            tenant_id=tenant_id,
            sources=sources or ["default"],
        )

        logger.info(
            "ioc_lifecycle_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            sources=initial_state.sources,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "ioc_lifecycle",
                    }
                },
            )
            final_state = IOCLifecycleState.model_validate(final_dict)
            self._results[session_id] = final_state

            logger.info(
                "ioc_lifecycle_runner.completed",
                session_id=session_id,
                iocs=len(final_state.iocs),
                enrichments=len(final_state.enrichments),
                false_positives=(final_state.false_positive_count),
            )
            return final_state

        except Exception as e:
            logger.error(
                "ioc_lifecycle_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = IOCLifecycleState(
                request_id=session_id,
                tenant_id=tenant_id,
                error=str(e),
                stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> IOCLifecycleState | None:
        """Retrieve a past lifecycle result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all lifecycle results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "iocs": len(state.iocs),
                "enrichments": len(state.enrichments),
                "false_positives": (state.false_positive_count),
                "stage": state.stage,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

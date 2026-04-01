"""Adaptive Access Controller runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.adaptive_access_controller.graph import (
    create_adaptive_access_controller_graph,
)
from shieldops.agents.adaptive_access_controller.models import (
    AdaptiveAccessControllerState,
)
from shieldops.agents.adaptive_access_controller.nodes import (
    set_toolkit,
)
from shieldops.agents.adaptive_access_controller.tools import (
    AdaptiveAccessControllerToolkit,
)

logger = structlog.get_logger()


class AdaptiveAccessControllerRunner:
    """Runner for the Adaptive Access Controller Agent."""

    def __init__(
        self,
        identity_client: Any | None = None,
        policy_engine: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AdaptiveAccessControllerToolkit(
            identity_client=identity_client,
            policy_engine=policy_engine,
            threat_intel=threat_intel,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_adaptive_access_controller_graph()
        self._app = graph.compile()
        self._results: dict[str, AdaptiveAccessControllerState] = {}
        logger.info("aac_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AdaptiveAccessControllerState:
        """Run adaptive access control workflow."""
        sid = f"aac-{uuid4().hex[:12]}"
        initial = AdaptiveAccessControllerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "aac_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "adaptive_access_controller",
                    },
                },
            )
            final = AdaptiveAccessControllerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "aac_runner.completed",
                session_id=sid,
                contexts=len(final.access_contexts),
                enforcements=len(final.enforcement_results),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "aac_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = AdaptiveAccessControllerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> AdaptiveAccessControllerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "contexts": len(s.access_contexts),
                "enforcements": len(
                    s.enforcement_results,
                ),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

"""Security Signal Router runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_signal_router.graph import (
    create_security_signal_router_graph,
)
from shieldops.agents.security_signal_router.models import (
    SecuritySignalRouterState,
)
from shieldops.agents.security_signal_router.nodes import (
    set_toolkit,
)
from shieldops.agents.security_signal_router.tools import (
    SecuritySignalRouterToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecuritySignalRouterRunner:
    """Runner for the Security Signal Router Agent."""

    def __init__(
        self,
        signal_bus: Any | None = None,
        agent_registry: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecuritySignalRouterToolkit(
            signal_bus=signal_bus,
            agent_registry=agent_registry,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_signal_router_graph()
        self._app = graph.compile()
        self._results: dict[str, SecuritySignalRouterState] = {}
        logger.info("ssr_runner.initialized")

    @enforced("security_signal_router")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecuritySignalRouterState:
        """Run signal routing workflow."""
        sid = f"ssr-{uuid4().hex[:12]}"
        initial = SecuritySignalRouterState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "ssr_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_signal_router",
                    },
                },
            )
            final = SecuritySignalRouterState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "ssr_runner.completed",
                session_id=sid,
                signals=len(final.signals),
                dispatched=len(final.dispatch_results),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ssr_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecuritySignalRouterState(
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
    ) -> SecuritySignalRouterState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "signals": len(s.signals),
                "dispatched": len(s.dispatch_results),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

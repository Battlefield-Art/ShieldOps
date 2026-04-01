"""Multi-Tenant Isolation Guard runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.multi_tenant_isolation_guard.graph import (
    create_multi_tenant_isolation_guard_graph,
)
from shieldops.agents.multi_tenant_isolation_guard.models import (
    MultiTenantIsolationGuardState,
)
from shieldops.agents.multi_tenant_isolation_guard.nodes import (
    set_toolkit,
)
from shieldops.agents.multi_tenant_isolation_guard.tools import (
    MultiTenantIsolationGuardToolkit,
)

logger = structlog.get_logger()


class MultiTenantIsolationGuardRunner:
    """Runner for the Multi-Tenant Isolation Guard Agent."""

    def __init__(
        self,
        platform_client: Any | None = None,
        network_scanner: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MultiTenantIsolationGuardToolkit(
            platform_client=platform_client,
            network_scanner=network_scanner,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_multi_tenant_isolation_guard_graph()
        self._app = graph.compile()
        self._results: dict[str, MultiTenantIsolationGuardState] = {}
        logger.info("mtig_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> MultiTenantIsolationGuardState:
        """Run isolation guard workflow."""
        sid = f"mtig-{uuid4().hex[:12]}"
        initial = MultiTenantIsolationGuardState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "mtig_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": ("multi_tenant_isolation_guard"),
                    },
                },
            )
            final = MultiTenantIsolationGuardState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "mtig_runner.completed",
                session_id=sid,
                tenants=len(final.tenant_mappings),
                enforcements=len(
                    final.control_enforcements,
                ),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "mtig_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = MultiTenantIsolationGuardState(
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
    ) -> MultiTenantIsolationGuardState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenants": len(s.tenant_mappings),
                "enforcements": len(
                    s.control_enforcements,
                ),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

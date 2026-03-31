"""Zero Day Hunter Agent runner — entry point for
executing zero-day hunting workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.zero_day_hunter.graph import (
    create_zero_day_hunter_graph,
)
from shieldops.agents.zero_day_hunter.models import (
    ZeroDayHunterState,
)
from shieldops.agents.zero_day_hunter.nodes import (
    set_toolkit,
)
from shieldops.agents.zero_day_hunter.tools import (
    ZeroDayHunterToolkit,
)

logger = structlog.get_logger()


class ZeroDayHunterRunner:
    """Runner for the Zero Day Hunter Agent."""

    def __init__(
        self,
        threat_feed: Any | None = None,
        vuln_db: Any | None = None,
        asset_inventory: Any | None = None,
        ids_engine: Any | None = None,
        edr_connector: Any | None = None,
        waf_connector: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ZeroDayHunterToolkit(
            threat_feed=threat_feed,
            vuln_db=vuln_db,
            asset_inventory=asset_inventory,
            ids_engine=ids_engine,
            edr_connector=edr_connector,
            waf_connector=waf_connector,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_zero_day_hunter_graph()
        self._app = graph.compile()
        self._results: dict[str, ZeroDayHunterState] = {}
        logger.info("zdh_runner.initialized")

    async def hunt(
        self,
        tenant_id: str = "",
        hours_back: int = 24,
        context: dict[str, Any] | None = None,
    ) -> ZeroDayHunterState:
        """Execute a zero-day hunting workflow."""
        request_id = f"zdh-{uuid4().hex[:12]}"

        initial_state = ZeroDayHunterState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "zdh_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            hours_back=hours_back,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "zero_day_hunter",
                    },
                },
            )
            final = ZeroDayHunterState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "zdh_runner.completed",
                request_id=request_id,
                zero_days=final.zero_days_found,
                critical=final.critical_exposures,
                signatures=final.signatures_deployed,
                mitigations=final.mitigations_applied,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "zdh_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ZeroDayHunterState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> ZeroDayHunterState | None:
        """Retrieve a cached hunting result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all hunting results as summaries."""
        return [
            {
                "request_id": rid,
                "zero_days": s.zero_days_found,
                "critical": s.critical_exposures,
                "signatures": s.signatures_deployed,
                "mitigations": s.mitigations_applied,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

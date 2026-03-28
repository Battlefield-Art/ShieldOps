"""Continuous Scanner Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.continuous_scanner.graph import (
    create_continuous_scanner_graph,
)
from shieldops.agents.continuous_scanner.models import (
    ContinuousScannerState,
)
from shieldops.agents.continuous_scanner.nodes import (
    set_toolkit,
)
from shieldops.agents.continuous_scanner.tools import (
    ContinuousScannerToolkit,
)

logger = structlog.get_logger()


class ContinuousScannerRunner:
    """Runner for the Continuous Scanner Agent."""

    def __init__(
        self,
        schedule_store: Any | None = None,
        agent_registry: Any | None = None,
        result_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ContinuousScannerToolkit(
            schedule_store=schedule_store,
            agent_registry=agent_registry,
            result_store=result_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_continuous_scanner_graph()
        self._app = graph.compile()
        self._results: dict[str, ContinuousScannerState] = {}
        logger.info("continuous_scanner_runner.initialized")

    async def scan(
        self,
        tenant_id: str,
    ) -> ContinuousScannerState:
        """Run continuous scanning cycle."""
        sid = f"scan-{uuid4().hex[:12]}"
        initial = ContinuousScannerState(
            tenant_id=tenant_id,
            request_id=sid,
        )

        logger.info(
            "continuous_scanner_runner.starting",
            session_id=sid,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "continuous_scanner",
                    }
                },
            )
            final = ContinuousScannerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "continuous_scanner_runner.completed",
                session_id=sid,
                scans_today=final.scans_run_today,
                coverage=final.coverage_pct,
                completed=len(final.completed),
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "continuous_scanner_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err = ContinuousScannerState(
                tenant_id=tenant_id,
                request_id=sid,
                error=str(e),
            )
            self._results[sid] = err
            return err

    def get_result(
        self,
        session_id: str,
    ) -> ContinuousScannerState | None:
        """Retrieve a stored result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scanning cycle summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "scans_today": s.scans_run_today,
                "coverage": s.coverage_pct,
                "completed": len(s.completed),
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

"""Finding Correlator Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.finding_correlator.graph import (
    create_finding_correlator_graph,
)
from shieldops.agents.finding_correlator.models import (
    FindingCorrelatorState,
)
from shieldops.agents.finding_correlator.nodes import (
    set_toolkit,
)
from shieldops.agents.finding_correlator.tools import (
    FindingCorrelatorToolkit,
)

logger = structlog.get_logger()


class FindingCorrelatorRunner:
    """Runner for the Finding Correlator Agent."""

    def __init__(
        self,
        finding_sources: Any | None = None,
        asset_inventory: Any | None = None,
        vuln_database: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = FindingCorrelatorToolkit(
            finding_sources=finding_sources,
            asset_inventory=asset_inventory,
            vuln_database=vuln_database,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_finding_correlator_graph()
        self._app = graph.compile()
        self._results: dict[str, FindingCorrelatorState] = {}
        logger.info("finding_correlator_runner.initialized")

    async def correlate(
        self,
        tenant_id: str,
    ) -> FindingCorrelatorState:
        """Run finding correlation."""
        sid = f"corr-{uuid4().hex[:12]}"
        initial = FindingCorrelatorState(
            tenant_id=tenant_id,
            request_id=sid,
        )

        logger.info(
            "finding_correlator_runner.starting",
            session_id=sid,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "finding_correlator",
                    }
                },
            )
            final = FindingCorrelatorState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "finding_correlator_runner.completed",
                session_id=sid,
                raw=len(final.raw_findings),
                deduped=len(final.deduplicated),
                dupes=final.duplicates_removed,
                groups=final.correlation_groups,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "finding_correlator_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err = FindingCorrelatorState(
                tenant_id=tenant_id,
                request_id=sid,
                error=str(e),
            )
            self._results[sid] = err
            return err

    def get_result(
        self,
        session_id: str,
    ) -> FindingCorrelatorState | None:
        """Retrieve a stored result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all correlation run summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "raw": len(s.raw_findings),
                "deduped": len(s.deduplicated),
                "dupes": s.duplicates_removed,
                "groups": s.correlation_groups,
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

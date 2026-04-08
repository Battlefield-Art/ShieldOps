"""Threat Feed Aggregator Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import ThreatFeedAggregatorToolkit

logger = structlog.get_logger()


class ThreatFeedAggregatorRunner:
    """Runs the Threat Feed Aggregator workflow."""

    def __init__(
        self,
        misp_client: Any | None = None,
        taxii_client: Any | None = None,
        otx_client: Any | None = None,
        vt_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatFeedAggregatorToolkit(
            misp_client=misp_client,
            taxii_client=taxii_client,
            otx_client=otx_client,
            vt_client=vt_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("tfa_runner.init")

    @enforced("threat_feed_aggregator")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute threat feed aggregation."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "tfa_runner.execute",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            self._results[request_id] = result
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "tfa_runner.execute.error",
            )
            raise

    def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a cached result."""
        return self._results.get(request_id)

    def list_results(
        self,
    ) -> list[dict[str, Any]]:
        """List all cached results."""
        return [
            {
                "request_id": rid,
                "tenant_id": r.get(
                    "tenant_id",
                    "",
                ),
                "total_iocs": r.get(
                    "total_iocs",
                    0,
                ),
                "high_severity": r.get(
                    "high_severity_count",
                    0,
                ),
                "error": r.get("error", ""),
            }
            for rid, r in self._results.items()
        ]

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        if self._repository:
            await self._repository.save(result)

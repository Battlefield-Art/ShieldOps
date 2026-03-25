"""Vendor Normalizer Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .tools import VendorNormalizerToolkit

logger = structlog.get_logger()


class VendorNormalizerRunner:
    """Runs the Vendor Normalizer agent workflow."""

    def __init__(
        self,
        schema_registry: Any | None = None,
        enrichment_service: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = VendorNormalizerToolkit(
            schema_registry=schema_registry,
            enrichment_service=enrichment_service,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("vendor_normalizer_runner.init")

    async def normalize(
        self,
        events: list[dict[str, Any]],
        vendor: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full vendor normalization pipeline.

        Args:
            events: List of raw vendor event dicts to normalize.
            vendor: Optional vendor hint to pre-tag all events.

        Returns:
            Final pipeline state including enriched OCSF events and stats.
        """
        request_id = f"vnorm-{int(time.time() * 1000)}"
        session_start = str(time.time())

        # Pre-tag vendor if provided
        if vendor:
            for evt in events:
                evt.setdefault("vendor", vendor)

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "vendor_events": events,
            "session_start": session_start,
            "reasoning_chain": [],
        }

        logger.info(
            "vendor_normalizer_runner.normalize",
            request_id=request_id,
            event_count=len(events),
            vendor=vendor,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("vendor_normalizer_runner.normalize.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist normalization results."""
        if self._repository:
            await self._repository.save_normalized_events(result)

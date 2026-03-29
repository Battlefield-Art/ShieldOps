"""WAF Manager — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import WAFManagerToolkit

logger = structlog.get_logger()


class WAFManagerRunner:
    """Runs the WAF Manager workflow."""

    def __init__(
        self,
        waf_client: Any | None = None,
        log_store: Any | None = None,
        alert_sink: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = WAFManagerToolkit(
            waf_client=waf_client,
            log_store=log_store,
            alert_sink=alert_sink,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("waf_manager_runner.init")

    async def run(
        self,
        tenant_id: str = "",
        waf_provider: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full WAF management workflow."""
        context = context or {}
        window = context.get("time_window_hours", 24)

        initial_state: dict[str, Any] = {
            "tenant_id": tenant_id,
            "waf_provider": waf_provider,
            "time_window_hours": window,
            "reasoning_chain": [],
        }

        logger.info(
            "waf_manager_runner.run",
            tenant_id=tenant_id,
            waf_provider=waf_provider,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("waf_manager_runner.run.error")
            raise

    async def analyze_only(
        self,
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Run attack analysis without auto-blocking."""
        logger.info(
            "waf_manager_runner.analyze_only",
            tenant_id=tenant_id,
        )
        events = await self._toolkit.ingest_waf_logs()
        summary = await self._toolkit.analyze_attack_patterns(events)
        return {
            "tenant_id": tenant_id,
            "attack_summary": summary,
            "event_count": len(events),
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist WAF management results."""
        if self._repository:
            await self._repository.save_waf_run(result)

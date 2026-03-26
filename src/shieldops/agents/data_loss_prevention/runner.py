"""Data Loss Prevention Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DataLossPreventionToolkit

logger = structlog.get_logger()


class DataLossPreventionRunner:
    """Runs the Data Loss Prevention workflow."""

    def __init__(
        self,
        endpoint_connector: Any | None = None,
        cloud_connector: Any | None = None,
        browser_connector: Any | None = None,
        ai_pipeline_connector: Any | None = None,
        mcp_connector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataLossPreventionToolkit(
            endpoint_connector=endpoint_connector,
            cloud_connector=cloud_connector,
            browser_connector=browser_connector,
            ai_pipeline_connector=ai_pipeline_connector,
            mcp_connector=mcp_connector,
            policy_engine=policy_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("dlp_runner.init")

    async def protect(
        self,
        tenant_id: str,
        channels: list[str] | None = None,
        time_window_hours: int = 24,
        content_samples: (dict[str, list[str]] | None) = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full DLP protection workflow.

        Args:
            tenant_id: Tenant identifier.
            channels: Optional channel filter list.
            time_window_hours: Lookback window for flow
                discovery.
            content_samples: Optional mapping of flow_id
                to sample content for regex classification.
            context: Additional context parameters.

        Returns:
            Final graph state with flows, records,
            attempts, policies, incidents, and stats.
        """
        context = context or {}
        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", ""),
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        if channels:
            initial_state["channels"] = channels
        if time_window_hours != 24:
            initial_state["time_window_hours"] = time_window_hours
        if content_samples:
            initial_state["content_samples"] = content_samples

        logger.info(
            "dlp_runner.protect",
            tenant_id=tenant_id,
            channels=channels,
            window_hours=time_window_hours,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("dlp_runner.protect.error")
            raise

    async def discover_only(
        self,
        tenant_id: str,
        channels: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run only the discovery phase.

        Useful for inventory without enforcement.
        """
        logger.info(
            "dlp_runner.discover_only",
            tenant_id=tenant_id,
        )
        flows = await self._toolkit.discover_data_flows(
            tenant_id=tenant_id,
            channels=channels,
        )
        return [f.model_dump() for f in flows]

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist DLP results."""
        if self._repository:
            await self._repository.save_dlp_run(result)

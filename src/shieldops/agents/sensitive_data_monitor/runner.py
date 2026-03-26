"""Sensitive Data Monitor Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SensitiveDataMonitorToolkit

logger = structlog.get_logger()


class SensitiveDataMonitorRunner:
    """Runs the Sensitive Data Monitor workflow."""

    def __init__(
        self,
        db_connector: Any | None = None,
        storage_connector: Any | None = None,
        ai_pipeline_connector: Any | None = None,
        control_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SensitiveDataMonitorToolkit(
            db_connector=db_connector,
            storage_connector=storage_connector,
            ai_pipeline_connector=(ai_pipeline_connector),
            control_api=control_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("sensitive_data_monitor_runner.init")

    async def monitor(
        self,
        tenant_id: str,
        source_configs: (list[dict[str, Any]] | None) = None,
        sample_data: (dict[str, list[str]] | None) = None,
        include_ai_pipelines: bool = True,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full monitoring workflow.

        Args:
            tenant_id: Tenant identifier.
            source_configs: Optional data source configs.
                If omitted, the agent auto-discovers.
            sample_data: Optional mapping of source_id
                to sample values for regex scanning.
            include_ai_pipelines: Whether to scan AI
                pipeline data (prompts, RAG, training).
            context: Additional context parameters.

        Returns:
            Final graph state with hits, classifications,
            exposures, controls, and compliance coverage.
        """
        context = context or {}
        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", ""),
            "tenant_id": tenant_id,
            "sources_scanned": source_configs or [],
            "include_ai_pipelines": (include_ai_pipelines),
            "reasoning_chain": [],
        }
        if sample_data:
            initial_state["sample_data"] = sample_data

        logger.info(
            "sensitive_data_monitor_runner.monitor",
            tenant_id=tenant_id,
            source_count=len(source_configs or []),
            include_ai=include_ai_pipelines,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("sensitive_data_monitor_runner.monitor.error")
            raise

    async def discover_only(
        self,
        tenant_id: str,
        source_configs: (list[dict[str, Any]] | None) = None,
        include_ai_pipelines: bool = True,
    ) -> list[dict[str, Any]]:
        """Run only discovery phase to inventory data sources.

        Useful for inventory without full monitoring.
        """
        logger.info(
            "sensitive_data_monitor_runner.discover_only",
            tenant_id=tenant_id,
        )
        sources = await self._toolkit.discover_data_sources(
            tenant_id=tenant_id,
            source_configs=source_configs,
            include_ai_pipelines=(include_ai_pipelines),
        )
        return [s.model_dump() for s in sources]

    async def scan_only(
        self,
        tenant_id: str,
        source_configs: (list[dict[str, Any]] | None) = None,
    ) -> list[dict[str, Any]]:
        """Run discovery + scan without classification or controls."""
        logger.info(
            "sensitive_data_monitor_runner.scan_only",
            tenant_id=tenant_id,
        )
        sources = await self._toolkit.discover_data_sources(
            tenant_id=tenant_id,
            source_configs=source_configs,
        )
        hits = await self._toolkit.scan_for_sensitive(sources)
        return [h.model_dump() for h in hits]

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist monitoring results."""
        if self._repository:
            await self._repository.save_monitor_run(result)

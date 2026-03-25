"""Data Classification Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DataClassificationToolkit

logger = structlog.get_logger()


class DataClassificationRunner:
    """Runs the Data Classification workflow."""

    def __init__(
        self,
        db_connector: Any | None = None,
        storage_connector: Any | None = None,
        label_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataClassificationToolkit(
            db_connector=db_connector,
            storage_connector=storage_connector,
            label_api=label_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("data_classification_runner.init")

    async def classify(
        self,
        tenant_id: str,
        source_configs: list[dict[str, Any]] | None = None,
        sample_data: dict[str, list[str]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full data classification workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            source_configs: Optional list of data asset configs to scan.
                If omitted, the agent performs auto-discovery.
            sample_data: Optional mapping of asset_id → sample values
                for regex-based detection.
            context: Additional context parameters.

        Returns:
            Final graph state with findings, mappings, labels, and stats.
        """
        context = context or {}
        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", ""),
            "tenant_id": tenant_id,
            "data_assets": source_configs or [],
            "reasoning_chain": [],
        }
        if sample_data:
            initial_state["sample_data"] = sample_data

        logger.info(
            "data_classification_runner.classify",
            tenant_id=tenant_id,
            source_count=len(source_configs or []),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("data_classification_runner.classify.error")
            raise

    async def scan_only(
        self,
        tenant_id: str,
        source_configs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Run only the scan phase to discover data assets.

        Useful for inventory without full classification.
        """
        logger.info(
            "data_classification_runner.scan_only",
            tenant_id=tenant_id,
        )
        assets = await self._toolkit.scan_data_sources(
            tenant_id=tenant_id,
            source_configs=source_configs,
        )
        return [a.model_dump() for a in assets]

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist classification results."""
        if self._repository:
            await self._repository.save_classification_run(result)

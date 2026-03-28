"""Data Encryption Monitor Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DataEncryptionMonitorToolkit

logger = structlog.get_logger()


class DataEncryptionMonitorRunner:
    """Runs the Data Encryption Monitor workflow."""

    def __init__(
        self,
        aws_connector: Any | None = None,
        gcp_connector: Any | None = None,
        azure_connector: Any | None = None,
        vault_connector: Any | None = None,
        certificate_connector: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataEncryptionMonitorToolkit(
            aws_connector=aws_connector,
            gcp_connector=gcp_connector,
            azure_connector=azure_connector,
            vault_connector=vault_connector,
            certificate_connector=certificate_connector,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("encryption_monitor_runner.init")

    async def monitor(
        self,
        tenant_id: str,
        cloud_providers: list[str] | None = None,
        asset_types: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full encryption monitoring workflow.

        Args:
            tenant_id: Tenant identifier.
            cloud_providers: Optional cloud provider filter.
            asset_types: Optional asset type filter.
            context: Additional context parameters.

        Returns:
            Final graph state with assets, keys, certs,
            gaps, and stats.
        """
        context = context or {}
        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", ""),
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        if cloud_providers:
            initial_state["cloud_providers"] = cloud_providers
        if asset_types:
            initial_state["asset_types"] = asset_types

        logger.info(
            "encryption_monitor_runner.monitor",
            tenant_id=tenant_id,
            providers=cloud_providers,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("encryption_monitor_runner.monitor.error")
            raise

    async def scan_only(
        self,
        tenant_id: str,
        cloud_providers: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run only the asset scan phase.

        Useful for inventory without full assessment.
        """
        logger.info(
            "encryption_monitor_runner.scan_only",
            tenant_id=tenant_id,
        )
        assets = await self._toolkit.scan_assets(
            tenant_id=tenant_id,
            cloud_providers=cloud_providers,
        )
        return [a.model_dump() for a in assets]

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist encryption monitor results."""
        if self._repository:
            await self._repository.save_encryption_run(result)

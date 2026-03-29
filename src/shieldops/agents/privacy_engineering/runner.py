"""Privacy Engineering Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import PrivacyEngineeringToolkit

logger = structlog.get_logger()


class PrivacyEngineeringRunner:
    """Runs the Privacy Engineering workflow."""

    def __init__(
        self,
        pipeline_registry: Any | None = None,
        pet_scanner: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PrivacyEngineeringToolkit(
            pipeline_registry=pipeline_registry,
            pet_scanner=pet_scanner,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("privacy_engineering_runner.init")

    async def assess(
        self,
        tenant_id: str,
        pipeline_configs: list[dict[str, Any]] | None = None,
        anonymization_configs: dict[str, dict[str, Any]] | None = None,
        pet_configs: dict[str, dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full privacy engineering workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            pipeline_configs: Optional list of pipeline configs to scan.
                If omitted, the agent performs auto-discovery.
            anonymization_configs: Optional mapping of pipeline_id -> anonymization
                parameters for detailed assessment.
            pet_configs: Optional mapping of pipeline_id -> PET configuration
                for implementation auditing.
            context: Additional context parameters.

        Returns:
            Final graph state with findings, PET audits, compliance, and stats.
        """
        context = context or {}
        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", f"pe-{tenant_id}"),
            "tenant_id": tenant_id,
            "pipelines": pipeline_configs or [],
            "reasoning_chain": [],
        }
        if anonymization_configs:
            initial_state["anonymization_configs"] = anonymization_configs
        if pet_configs:
            initial_state["pet_configs"] = pet_configs

        logger.info(
            "privacy_engineering_runner.assess",
            tenant_id=tenant_id,
            pipeline_count=len(pipeline_configs or []),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("privacy_engineering_runner.assess.error")
            raise

    async def scan_only(
        self,
        tenant_id: str,
        pipeline_configs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Run only the scan phase to discover data pipelines.

        Useful for inventory without full privacy assessment.
        """
        logger.info(
            "privacy_engineering_runner.scan_only",
            tenant_id=tenant_id,
        )
        pipelines = await self._toolkit.scan_pipelines(
            tenant_id=tenant_id,
            pipeline_configs=pipeline_configs,
        )
        return [p.model_dump() for p in pipelines]

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist privacy assessment results."""
        if self._repository:
            await self._repository.save_privacy_assessment(result)

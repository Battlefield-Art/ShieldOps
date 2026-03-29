"""Data Sovereignty Enforcer Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DataSovereigntyEnforcerToolkit

logger = structlog.get_logger()


class DataSovereigntyEnforcerRunner:
    """Runs the Data Sovereignty Enforcer workflow."""

    PREFIX = "dse-"

    def __init__(
        self,
        flow_connector: Any | None = None,
        policy_engine: Any | None = None,
        geo_fence_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataSovereigntyEnforcerToolkit(
            flow_connector=flow_connector,
            policy_engine=policy_engine,
            geo_fence_api=geo_fence_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("data_sovereignty_enforcer_runner.init")

    async def enforce(
        self,
        tenant_id: str,
        flow_configs: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full data sovereignty enforcement workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            flow_configs: Optional list of data flow configs to analyze.
                If omitted, the agent performs auto-discovery.
            context: Additional context parameters.

        Returns:
            Final graph state with violations, validations, enforcements, and stats.
        """
        context = context or {}
        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", f"{self.PREFIX}{tenant_id}"),
            "tenant_id": tenant_id,
            "data_flows": flow_configs or [],
            "reasoning_chain": [],
        }

        logger.info(
            "data_sovereignty_enforcer_runner.enforce",
            tenant_id=tenant_id,
            flow_count=len(flow_configs or []),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("data_sovereignty_enforcer_runner.enforce.error")
            raise

    async def discover_only(
        self,
        tenant_id: str,
        flow_configs: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Run only the discovery phase to inventory data flows.

        Useful for mapping data flows without full enforcement.
        """
        logger.info(
            "data_sovereignty_enforcer_runner.discover_only",
            tenant_id=tenant_id,
        )
        flows = await self._toolkit.discover_data_flows(
            tenant_id=tenant_id,
            flow_configs=flow_configs,
        )
        return [f.model_dump() for f in flows]

    async def check_compliance(
        self,
        tenant_id: str,
        flow_configs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run discovery + jurisdiction mapping + residency check (no enforcement).

        Returns violations and transfer validations without applying policies.
        """
        logger.info(
            "data_sovereignty_enforcer_runner.check_compliance",
            tenant_id=tenant_id,
        )
        flows = await self._toolkit.discover_data_flows(
            tenant_id=tenant_id,
            flow_configs=flow_configs,
        )
        mappings = await self._toolkit.map_jurisdictions(flows)
        violations = await self._toolkit.check_residency(flows, mappings)
        validations = await self._toolkit.validate_transfers(flows, mappings)

        return {
            "data_flows": [f.model_dump() for f in flows],
            "jurisdiction_mappings": [m.model_dump() for m in mappings],
            "residency_violations": [v.model_dump() for v in violations],
            "transfer_validations": [v.model_dump() for v in validations],
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist sovereignty enforcement results."""
        if self._repository:
            await self._repository.save_sovereignty_run(result)

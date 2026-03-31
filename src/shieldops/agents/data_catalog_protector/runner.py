"""Data Catalog Protector Agent runner — entry point
for executing catalog security scans."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_catalog_protector.graph import (
    create_data_catalog_protector_graph,
)
from shieldops.agents.data_catalog_protector.models import (
    DataCatalogProtectorState,
)
from shieldops.agents.data_catalog_protector.nodes import (
    set_toolkit,
)
from shieldops.agents.data_catalog_protector.tools import (
    DataCatalogProtectorToolkit,
)

logger = structlog.get_logger()


class DataCatalogProtectorRunner:
    """Runner for the Data Catalog Protector Agent."""

    def __init__(
        self,
        catalog_client: Any | None = None,
        access_store: Any | None = None,
        policy_engine: Any | None = None,
        classification_engine: Any | None = None,
        enforcement_client: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataCatalogProtectorToolkit(
            catalog_client=catalog_client,
            access_store=access_store,
            policy_engine=policy_engine,
            classification_engine=classification_engine,
            enforcement_client=enforcement_client,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_data_catalog_protector_graph()
        self._app = graph.compile()
        self._results: dict[str, DataCatalogProtectorState] = {}
        logger.info("dcp_runner.initialized")

    async def protect(
        self,
        catalog_names: list[str],
        scan_scope: dict[str, Any] | None = None,
        policy_rules: list[dict[str, Any]] | None = None,
        tenant_id: str = "",
    ) -> DataCatalogProtectorState:
        """Run a catalog protection scan."""
        request_id = f"dcp-{uuid4().hex[:12]}"

        initial_state = DataCatalogProtectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            catalog_names=catalog_names,
            scan_scope=scan_scope or {},
            policy_rules=policy_rules or [],
        )

        logger.info(
            "dcp_runner.starting",
            request_id=request_id,
            catalogs=len(catalog_names),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "data_catalog_protector",
                    },
                },
            )
            final = DataCatalogProtectorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "dcp_runner.completed",
                request_id=request_id,
                tables=final.total_tables_scanned,
                pii=final.pii_detected,
                violations=final.violations_found,
                enforced=final.enforcements_applied,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dcp_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = DataCatalogProtectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                catalog_names=catalog_names,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> DataCatalogProtectorState | None:
        """Retrieve a cached scan result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results as summaries."""
        return [
            {
                "request_id": rid,
                "catalogs": s.catalog_names,
                "tables_scanned": s.total_tables_scanned,
                "pii_detected": s.pii_detected,
                "violations": s.violations_found,
                "enforced": s.enforcements_applied,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

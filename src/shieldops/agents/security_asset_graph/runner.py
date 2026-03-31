"""Security Asset Graph Agent runner — entry point
for executing asset relationship and dependency mapping."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_asset_graph.graph import (
    create_security_asset_graph_graph,
)
from shieldops.agents.security_asset_graph.models import (
    SecurityAssetGraphState,
)
from shieldops.agents.security_asset_graph.nodes import (
    set_toolkit,
)
from shieldops.agents.security_asset_graph.tools import (
    SecurityAssetGraphToolkit,
)

logger = structlog.get_logger()


class SecurityAssetGraphRunner:
    """Runner for the Security Asset Graph Agent."""

    def __init__(
        self,
        cmdb_client: Any | None = None,
        network_scanner: Any | None = None,
        impact_analyzer: Any | None = None,
        path_finder: Any | None = None,
        risk_scorer: Any | None = None,
        metrics_tracker: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityAssetGraphToolkit(
            cmdb_client=cmdb_client,
            network_scanner=network_scanner,
            impact_analyzer=impact_analyzer,
            path_finder=path_finder,
            risk_scorer=risk_scorer,
            metrics_tracker=metrics_tracker,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_asset_graph_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityAssetGraphState] = {}
        logger.info("sag_runner.initialized")

    async def analyze(
        self,
        target_environment: str = "production",
        asset_types: list[str] | None = None,
        depth_limit: int = 5,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityAssetGraphState:
        """Run an asset graph analysis."""
        request_id = f"sag-{uuid4().hex[:12]}"

        initial_state = SecurityAssetGraphState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_environment=target_environment,
            asset_types=asset_types or [],
            depth_limit=depth_limit,
            scope=scope or {},
        )

        logger.info(
            "sag_runner.starting",
            request_id=request_id,
            environment=target_environment,
            depth_limit=depth_limit,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_asset_graph",
                    },
                },
            )
            final = SecurityAssetGraphState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sag_runner.completed",
                request_id=request_id,
                total_assets=final.total_assets,
                total_deps=final.total_dependencies,
                critical_paths=final.critical_path_count,
                overall_risk=final.overall_risk,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sag_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityAssetGraphState(
                request_id=request_id,
                tenant_id=tenant_id,
                target_environment=target_environment,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityAssetGraphState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "environment": s.target_environment,
                "total_assets": s.total_assets,
                "total_deps": s.total_dependencies,
                "critical_paths": s.critical_path_count,
                "overall_risk": s.overall_risk,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

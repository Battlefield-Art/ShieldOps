"""Threat Surface Analyzer Agent runner -- entry point for analysis cycles.

Takes environment configuration, constructs the LangGraph,
runs end-to-end, and returns completed TSA state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_surface_analyzer.graph import (
    create_threat_surface_analyzer_graph,
)
from shieldops.agents.threat_surface_analyzer.models import (
    ThreatSurfaceAnalyzerState,
)
from shieldops.agents.threat_surface_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_surface_analyzer.tools import (
    ThreatSurfaceAnalyzerToolkit,
)

logger = structlog.get_logger()


class ThreatSurfaceAnalyzerRunner:
    """Runs threat surface analysis workflows.

    Usage:
        runner = ThreatSurfaceAnalyzerRunner(
            asset_discovery_client=discovery,
            vulnerability_scanner=scanner,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        asset_discovery_client: Any | None = None,
        vulnerability_scanner: Any | None = None,
        cloud_inventory: Any | None = None,
        threat_intel_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatSurfaceAnalyzerToolkit(
            asset_discovery_client=asset_discovery_client,
            vulnerability_scanner=vulnerability_scanner,
            cloud_inventory=cloud_inventory,
            threat_intel_client=threat_intel_client,
            policy_engine=policy_engine,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_threat_surface_analyzer_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, ThreatSurfaceAnalyzerState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ThreatSurfaceAnalyzerState:
        """Run a full threat surface analysis cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed ThreatSurfaceAnalyzerState.
        """
        request_id = f"tsa-{uuid4().hex[:12]}"

        logger.info(
            "tsa_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = ThreatSurfaceAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = ThreatSurfaceAnalyzerState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "tsa_completed",
                request_id=request_id,
                assets=len(final_state.assets),
                exposures=len(final_state.exposures),
                risks=len(final_state.risks),
                critical=final_state.critical_count,
                mitigations=len(final_state.mitigations),
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "tsa_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatSurfaceAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> ThreatSurfaceAnalyzerState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": st.tenant_id,
                "stage": st.stage,
                "status": st.current_step,
                "assets": len(st.assets),
                "exposures": len(st.exposures),
                "risks": len(st.risks),
                "critical": st.critical_count,
                "high": st.high_count,
                "mitigations": len(st.mitigations),
                "overall_risk_score": st.overall_risk_score,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]

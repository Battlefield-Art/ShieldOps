"""Supply Chain Risk Engine Agent runner -- entry point.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed SCRE state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.supply_chain_risk_engine.graph import (
    create_supply_chain_risk_engine_graph,
)
from shieldops.agents.supply_chain_risk_engine.models import (
    SupplyChainRiskEngineState,
)
from shieldops.agents.supply_chain_risk_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.supply_chain_risk_engine.tools import (
    SupplyChainRiskEngineToolkit,
)

logger = structlog.get_logger()


class SupplyChainRiskEngineRunner:
    """Runs supply chain risk engine workflows.

    Usage:
        runner = SupplyChainRiskEngineRunner(
            package_registry=registry,
            vuln_scanner=scanner,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        package_registry: Any | None = None,
        vuln_scanner: Any | None = None,
        sbom_store: Any | None = None,
        dependency_graph: Any | None = None,
        remediation_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SupplyChainRiskEngineToolkit(
            package_registry=package_registry,
            vuln_scanner=vuln_scanner,
            sbom_store=sbom_store,
            dependency_graph=dependency_graph,
            remediation_engine=remediation_engine,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_supply_chain_risk_engine_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, SupplyChainRiskEngineState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SupplyChainRiskEngineState:
        """Run a full supply chain risk assessment cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed SupplyChainRiskEngineState.
        """
        request_id = f"scre-{uuid4().hex[:12]}"

        logger.info(
            "scre_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = SupplyChainRiskEngineState(
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

            final_state = SupplyChainRiskEngineState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "scre_completed",
                request_id=request_id,
                dependencies=final_state.dependency_count,
                vulnerabilities=(final_state.vulnerability_count),
                critical=final_state.critical_count,
                mitigations=len(final_state.mitigations),
                duration_ms=(final_state.session_duration_ms),
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "scre_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SupplyChainRiskEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SupplyChainRiskEngineState | None:
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
                "dependencies": st.dependency_count,
                "vulnerabilities": st.vulnerability_count,
                "critical": st.critical_count,
                "mitigations": len(st.mitigations),
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]

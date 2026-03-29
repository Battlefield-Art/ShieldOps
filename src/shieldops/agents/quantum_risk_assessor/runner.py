"""Quantum Risk Assessor Agent runner — entry point for
executing quantum risk assessment workflows.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.quantum_risk_assessor.graph import (
    create_quantum_risk_assessor_graph,
)
from shieldops.agents.quantum_risk_assessor.models import (
    QuantumRiskAssessorState,
)
from shieldops.agents.quantum_risk_assessor.nodes import (
    set_toolkit,
)
from shieldops.agents.quantum_risk_assessor.tools import (
    QuantumRiskAssessorToolkit,
)

logger = structlog.get_logger()


class QuantumRiskAssessorRunner:
    """Runner for the Quantum Risk Assessor Agent."""

    def __init__(
        self,
        client: Any | None = None,
    ) -> None:
        self._toolkit = QuantumRiskAssessorToolkit(
            client=client,
        )
        set_toolkit(self._toolkit)
        graph = create_quantum_risk_assessor_graph()
        self._app = graph.compile()
        self._results: dict[str, QuantumRiskAssessorState] = {}
        logger.info("quantum_risk_assessor_runner.initialized")

    async def execute(
        self,
        tenant_id: str,
        request_id: str | None = None,
        scan_config: dict[str, Any] | None = None,
    ) -> QuantumRiskAssessorState:
        """Run quantum risk assessment workflow.

        Args:
            tenant_id: Tenant identifier.
            request_id: Optional request ID.
            scan_config: Optional scan configuration
                with scope and target_types.

        Returns:
            Final QuantumRiskAssessorState with all
            crypto assets, algorithm inventory,
            vulnerability assessments, readiness scores,
            and migration recommendations.
        """
        rid = request_id or f"qra-{uuid4().hex[:12]}"
        initial_state = QuantumRiskAssessorState(
            request_id=rid,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "quantum_risk_assessor_runner.starting",
            request_id=rid,
            tenant_id=tenant_id,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "request_id": rid,
                        "agent": "quantum_risk_assessor",
                    },
                },
            )
            final_state = QuantumRiskAssessorState.model_validate(
                final_dict,
            )
            self._results[rid] = final_state

            logger.info(
                "quantum_risk_assessor_runner.completed",
                request_id=rid,
                crypto_assets=len(final_state.crypto_assets),
                vulnerable_algorithms=(final_state.vulnerable_algorithm_count),
                critical_assets=(final_state.critical_asset_count),
                total_risk=final_state.total_risk_score,
                pqc_readiness=(final_state.pqc_readiness_score),
                recommendations=len(final_state.migration_recommendations),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "quantum_risk_assessor_runner.failed",
                request_id=rid,
                error=str(e),
            )
            error_state = QuantumRiskAssessorState(
                request_id=rid,
                tenant_id=tenant_id,
                scan_config=scan_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[rid] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> QuantumRiskAssessorState | None:
        """Retrieve a previous assessment result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all assessment results."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "crypto_assets": len(state.crypto_assets),
                "vulnerable_algorithms": state.vulnerable_algorithm_count,
                "critical_assets": state.critical_asset_count,
                "total_risk_score": state.total_risk_score,
                "pqc_readiness_score": state.pqc_readiness_score,
                "recommendations": len(state.migration_recommendations),
                "current_step": state.current_step,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]

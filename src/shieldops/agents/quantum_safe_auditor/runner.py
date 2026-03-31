"""Quantum Safe Auditor runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.quantum_safe_auditor.graph import (
    create_quantum_safe_auditor_graph,
)
from shieldops.agents.quantum_safe_auditor.models import (
    QuantumSafeAuditorState,
)
from shieldops.agents.quantum_safe_auditor.nodes import (
    set_toolkit,
)
from shieldops.agents.quantum_safe_auditor.tools import (
    QuantumSafeAuditorToolkit,
)

logger = structlog.get_logger()


class QuantumSafeAuditorRunner:
    """Runner for the Quantum Safe Auditor Agent."""

    def __init__(
        self,
        crypto_scanner: Any | None = None,
        cert_manager: Any | None = None,
        risk_engine: Any | None = None,
        migration_planner: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = QuantumSafeAuditorToolkit(
            crypto_scanner=crypto_scanner,
            cert_manager=cert_manager,
            risk_engine=risk_engine,
            migration_planner=migration_planner,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_quantum_safe_auditor_graph()
        self._app = graph.compile()
        self._results: dict[str, QuantumSafeAuditorState] = {}
        logger.info("qsa_runner.initialized")

    async def audit(
        self,
        request_id: str,
        tenant_id: str = "",
        audit_config: dict[str, Any] | None = None,
    ) -> QuantumSafeAuditorState:
        """Run quantum-safe cryptography audit."""
        sid = f"qsa-{uuid4().hex[:12]}"
        initial = QuantumSafeAuditorState(
            request_id=request_id,
            tenant_id=tenant_id,
            audit_config=audit_config or {},
        )

        logger.info(
            "qsa_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "quantum_safe_auditor",
                    },
                },
            )
            final = QuantumSafeAuditorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "qsa_runner.completed",
                session_id=sid,
                crypto_assets=final.total_crypto_assets,
                vulnerable=final.vulnerable_count,
                plans=len(final.migration_plans),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "qsa_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = QuantumSafeAuditorState(
                request_id=request_id,
                tenant_id=tenant_id,
                audit_config=audit_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> QuantumSafeAuditorState | None:
        """Retrieve a previous audit result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all audit results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_crypto_assets": s.total_crypto_assets,
                "high_risk": s.high_risk_count,
                "vulnerable": s.vulnerable_count,
                "migration_plans": len(s.migration_plans),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

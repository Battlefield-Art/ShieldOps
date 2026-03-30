"""Security Config Assessor Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .models import BenchmarkType, ComplianceLevel
from .tools import SecurityConfigAssessorToolkit

logger = structlog.get_logger()


class SecurityConfigAssessorRunner:
    """Runs the Security Config Assessor agent workflow."""

    def __init__(
        self,
        infra_clients: Any | None = None,
        benchmark_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityConfigAssessorToolkit(
            infra_clients=infra_clients,
            benchmark_db=benchmark_db,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("sca_runner.init")

    async def assess(
        self,
        tenant_id: str,
        benchmarks: list[str] | None = None,
        compliance_level: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full security config assessment.

        Args:
            tenant_id: Tenant identifier.
            benchmarks: CIS benchmarks to evaluate.
            compliance_level: Level 1, Level 2, or custom.

        Returns:
            Final agent state with compliance score,
            drifts, remediation scripts, and stats.
        """
        if benchmarks is None:
            benchmarks = [b.value for b in BenchmarkType]

        if compliance_level is None:
            compliance_level = ComplianceLevel.LEVEL_1.value

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "benchmarks": benchmarks,
            "compliance_level": compliance_level,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "sca_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
            benchmarks=benchmarks,
            compliance_level=compliance_level,
        )

        try:
            result = await self._app.ainvoke(
                initial_state,  # type: ignore[arg-type]
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("sca_runner.assess.error")
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist assessment results."""
        if self._repository:
            await self._repository.save_assessment(result)

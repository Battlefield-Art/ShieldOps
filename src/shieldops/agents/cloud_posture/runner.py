"""Cloud Posture Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .models import BenchmarkFramework, CloudProvider
from .tools import CloudPostureToolkit

logger = structlog.get_logger()


class CloudPostureRunner:
    """Runs the Cloud Posture CSPM agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        benchmark_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudPostureToolkit(
            cloud_clients=cloud_clients,
            benchmark_db=benchmark_db,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_posture_runner.init")

    async def assess(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
        frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full cloud posture assessment workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            providers: Cloud providers to scan. Defaults to all supported.
            frameworks: Benchmark frameworks to evaluate. Defaults to CIS per provider.

        Returns:
            Final agent state with posture score, misconfigs, remediation actions,
            and summary statistics.
        """
        if providers is None:
            providers = [p.value for p in CloudProvider if p != CloudProvider.MULTI_CLOUD]

        if frameworks is None:
            frameworks = [f.value for f in BenchmarkFramework]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "providers": providers,
            "frameworks": frameworks,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cloud_posture_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
            frameworks=frameworks,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("cloud_posture_runner.assess.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist cloud posture assessment results."""
        if self._repository:
            await self._repository.save_posture_assessment(result)

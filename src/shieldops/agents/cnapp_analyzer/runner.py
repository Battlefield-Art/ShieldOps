"""CNAPP Analyzer Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .models import ComplianceFramework
from .tools import CNAPPAnalyzerToolkit

logger = structlog.get_logger()


class CNAPPAnalyzerRunner:
    """Runs the unified CNAPP Analyzer agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        workload_scanner: Any | None = None,
        identity_analyzer: Any | None = None,
        code_scanner: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CNAPPAnalyzerToolkit(
            cloud_clients=cloud_clients,
            workload_scanner=workload_scanner,
            identity_analyzer=identity_analyzer,
            code_scanner=code_scanner,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cnapp_analyzer_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
        frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute full CNAPP analysis workflow.

        Scans across CSPM, CWPP, CIEM, and code
        security domains, then correlates risks into
        a unified score.

        Args:
            tenant_id: Tenant identifier.
            providers: Cloud providers to scan.
                Defaults to aws, gcp, azure, kubernetes.
            frameworks: Compliance frameworks.
                Defaults to all supported.

        Returns:
            Final state with unified risk score,
            domain findings, compliance coverage,
            and summary statistics.
        """
        if providers is None:
            providers = [
                "aws",
                "gcp",
                "azure",
                "kubernetes",
            ]

        if frameworks is None:
            frameworks = [f.value for f in ComplianceFramework]

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
            "cnapp_analyzer_runner.analyze",
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
            logger.exception("cnapp_analyzer_runner.analyze.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist CNAPP analysis results."""
        if self._repository:
            await self._repository.save_cnapp_analysis(result)

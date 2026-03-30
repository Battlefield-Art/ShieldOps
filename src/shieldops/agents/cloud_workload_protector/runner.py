"""Cloud Workload Protector Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CloudWorkloadProtectorToolkit

logger = structlog.get_logger()


class CloudWorkloadProtectorRunner:
    """Runs the Cloud Workload Protector agent workflow."""

    def __init__(
        self,
        runtime_client: Any | None = None,
        vuln_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudWorkloadProtectorToolkit(
            runtime_client=runtime_client,
            vuln_db=vuln_db,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cwp_runner.init")

    async def protect(
        self,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Execute the full workload protection workflow.

        Args:
            tenant_id: Tenant identifier for isolation.

        Returns:
            Final agent state with protection score,
            anomalies, drift findings, vulnerabilities,
            containment actions, and summary stats.
        """
        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cwp_runner.protect",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "cwp_runner.protect.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist workload protection results."""
        if self._repository:
            await self._repository.save_cwp_result(
                result,
            )

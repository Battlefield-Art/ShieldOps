"""Multi-Cloud Compliance Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import MultiCloudComplianceToolkit

logger = structlog.get_logger()


class MultiCloudComplianceRunner:
    """Runs the Multi-Cloud Compliance agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MultiCloudComplianceToolkit(
            cloud_clients=cloud_clients,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("multi_cloud_compliance_runner.init")

    async def assess(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
        frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full compliance assessment."""
        if providers is None:
            providers = ["aws", "gcp", "azure"]
        if frameworks is None:
            frameworks = ["cis_aws", "cis_gcp", "cis_azure"]

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
            "multi_cloud_compliance_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("multi_cloud_compliance_runner.error")
            raise

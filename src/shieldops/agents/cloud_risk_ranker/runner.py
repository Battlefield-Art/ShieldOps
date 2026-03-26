"""Cloud Risk Ranker Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CloudRiskRankerToolkit

logger = structlog.get_logger()


class CloudRiskRankerRunner:
    """Runs the Cloud Risk Ranker agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        threat_intel_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudRiskRankerToolkit(
            cloud_clients=cloud_clients,
            threat_intel_client=threat_intel_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_risk_ranker_runner.init")

    async def rank(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full cloud risk ranking workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant
                isolation.
            providers: Cloud providers to scan. Defaults to
                all supported (aws, gcp, azure, kubernetes).

        Returns:
            Final agent state with ranked risks, attack
            paths, remediation priorities, and summary
            statistics.
        """
        if providers is None:
            providers = ["aws", "gcp", "azure", "kubernetes"]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "providers": providers,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cloud_risk_ranker_runner.rank",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
        )

        try:
            result = await self._app.ainvoke(
                initial_state  # type: ignore[arg-type]
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("cloud_risk_ranker_runner.rank.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist cloud risk ranking results."""
        if self._repository:
            await self._repository.save_risk_ranking(result)

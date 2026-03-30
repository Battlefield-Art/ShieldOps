"""IAM Policy Analyzer Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .models import CloudProvider
from .tools import IAMPolicyAnalyzerToolkit

logger = structlog.get_logger()


class IAMPolicyAnalyzerRunner:
    """Runs the IAM Policy Analyzer agent workflow."""

    def __init__(
        self,
        iam_clients: Any | None = None,
        usage_tracker: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IAMPolicyAnalyzerToolkit(
            iam_clients=iam_clients,
            usage_tracker=usage_tracker,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("iam_policy_analyzer_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full IAM policy analysis workflow.

        Args:
            tenant_id: Tenant identifier for isolation.
            providers: Cloud providers to analyze.
                Defaults to AWS, GCP, Azure.

        Returns:
            Final agent state with risk score, alerts,
            unused permissions, and recommendations.
        """
        if providers is None:
            providers = [p.value for p in CloudProvider if p != CloudProvider.OKTA]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "providers": providers,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "iam_policy_analyzer_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
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
                "iam_policy_analyzer_runner.analyze.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist IAM analysis results."""
        if self._repository:
            await self._repository.save_iam_analysis(
                result,
            )

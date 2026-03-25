"""Policy Engine Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .tools import PolicyEngineToolkit

logger = structlog.get_logger()


class PolicyEngineRunner:
    """Runs the Policy Engine agent workflow."""

    def __init__(
        self,
        opa_client: Any | None = None,
        policy_store: Any | None = None,
        compliance_registry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PolicyEngineToolkit(
            opa_client=opa_client,
            policy_store=policy_store,
            compliance_registry=compliance_registry,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("policy_engine_runner.init")

    async def evaluate(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full policy engine workflow.

        Collects requirements, generates OPA Rego policies, validates
        coverage, detects drift, reconciles where possible, and produces
        a summary report.
        """
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "session_start": time.time(),
            "reasoning_chain": [],
        }

        logger.info(
            "policy_engine_runner.evaluate",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,  # type: ignore[arg-type]
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("policy_engine_runner.evaluate.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist policy engine results."""
        if self._repository:
            await self._repository.save_policy_evaluation(result)

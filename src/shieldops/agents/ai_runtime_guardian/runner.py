"""AI Runtime Guardian Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AIRuntimeGuardianToolkit

logger = structlog.get_logger()


class AIRuntimeGuardianRunner:
    """Runs the AI Runtime Guardian agent workflow."""

    def __init__(
        self,
        runtime_api: Any | None = None,
        threat_feed: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AIRuntimeGuardianToolkit(
            runtime_api=runtime_api,
            threat_feed=threat_feed,
            policy_engine=policy_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("ai_guardian_runner.init")

    async def guard(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute AI runtime guardian workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "ai_guardian_runner.guard",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("ai_guardian_runner.guard.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_guard_result(result)

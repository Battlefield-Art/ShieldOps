"""AI Runtime Defense Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .tools import AIRuntimeDefenseToolkit

logger = structlog.get_logger()


class AIRuntimeDefenseRunner:
    """Runs the AI Runtime Defense agent workflow."""

    def __init__(
        self,
        firewall_client: Any | None = None,
        credential_manager: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AIRuntimeDefenseToolkit(
            firewall_client=firewall_client,
            credential_manager=credential_manager,
            threat_intel=threat_intel,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("ai_runtime_defense_runner.init")

    async def scan(
        self,
        app_id: str,
        context: dict[str, Any] | None = None,
        model_provider: str = "anthropic",
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full AI runtime defense scan workflow."""
        initial_state: dict[str, Any] = {
            "request_id": f"aird-{int(time.time())}",
            "app_id": app_id,
            "model_provider": model_provider,
            "deployment_context": context or {},
            "scan_scope": scan_scope or ["prompts", "outputs", "usage", "supply_chain"],
            "session_start": time.time(),
            "reasoning_chain": [],
        }

        logger.info(
            "ai_runtime_defense_runner.scan",
            app_id=app_id,
            model_provider=model_provider,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("ai_runtime_defense_runner.scan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist scan results."""
        if self._repository:
            await self._repository.save_scan_result(result)

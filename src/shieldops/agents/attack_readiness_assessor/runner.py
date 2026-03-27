"""Attack Readiness Assessor Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AttackReadinessAssessorToolkit

logger = structlog.get_logger()


class AttackReadinessAssessorRunner:
    """Runs the Attack Readiness Assessor workflow."""

    def __init__(
        self,
        threat_intel: Any | None = None,
        control_registry: Any | None = None,
        detection_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AttackReadinessAssessorToolkit(
            threat_intel=threat_intel,
            control_registry=control_registry,
            detection_engine=detection_engine,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info(
            "attack_readiness_runner.init",
        )

    async def assess(
        self,
        tenant_id: str,
        scenarios: list[str] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Run attack readiness assessment."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "scenarios": scenarios or [],
            "reasoning_chain": [],
        }

        logger.info(
            "attack_readiness_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
            scenarios=scenarios,
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
                "attack_readiness_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist assessment results."""
        if self._repository:
            await self._repository.save(result)

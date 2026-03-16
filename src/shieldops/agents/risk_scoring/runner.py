"""Risk Scoring Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import RiskScoringToolkit

logger = structlog.get_logger()


class RiskScoringRunner:
    """Runs the Risk Scoring agent workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        threat_intel: Any | None = None,
        asset_inventory: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RiskScoringToolkit(
            siem_client=siem_client,
            threat_intel=threat_intel,
            asset_inventory=asset_inventory,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("risk_scoring_runner.init")

    async def run(
        self,
        observations: list[dict[str, Any]] | None = None,
        time_window_hours: int = 24,
        autonomous_threshold: float = 0.85,
        approval_threshold: float = 0.5,
    ) -> dict[str, Any]:
        """Execute the full risk scoring workflow."""
        initial_state: dict[str, Any] = {
            "request_id": "",
            "time_window_hours": time_window_hours,
            "autonomous_threshold": autonomous_threshold,
            "approval_threshold": approval_threshold,
            "reasoning_chain": [],
        }
        if observations:
            initial_state["raw_observations"] = observations

        logger.info(
            "risk_scoring_runner.run",
            observation_count=len(observations) if observations else 0,
            window_hours=time_window_hours,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("risk_scoring_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist risk scoring results."""
        if self._repository:
            await self._repository.save_risk_scoring_run(result)

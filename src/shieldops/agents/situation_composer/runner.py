"""Situation Composer Agent runner — entry point for composing security situations."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.situation_composer.graph import create_situation_composer_graph
from shieldops.agents.situation_composer.models import SituationComposerState
from shieldops.agents.situation_composer.nodes import set_toolkit
from shieldops.agents.situation_composer.tools import SituationComposerToolkit

logger = structlog.get_logger()


class SituationComposerRunner:
    """Runner for the Situation Composer Agent."""

    def __init__(
        self,
        alert_store: Any | None = None,
        threat_intel: Any | None = None,
        asset_db: Any | None = None,
    ) -> None:
        self._toolkit = SituationComposerToolkit(
            alert_store=alert_store,
            threat_intel=threat_intel,
            asset_db=asset_db,
        )
        set_toolkit(self._toolkit)
        graph = create_situation_composer_graph(
            alert_store=alert_store,
            threat_intel=threat_intel,
            asset_db=asset_db,
        )
        self._app = graph.compile()
        self._results: dict[str, SituationComposerState] = {}
        logger.info("situation_composer_runner.initialized")

    async def compose(
        self,
        time_window_minutes: int = 60,
        vendors: list[str] | None = None,
    ) -> dict[str, Any]:
        """Compose a security situation from recent alerts.

        Args:
            time_window_minutes: How far back to look for alerts.
            vendors: Optional vendor filter (e.g. ["crowdstrike", "defender"]).

        Returns:
            Dict with situation, stats, reasoning_chain, and error fields.
        """
        session_id = f"compose-{uuid4().hex[:12]}"
        initial_state = SituationComposerState(
            request_id=session_id,
            stats={
                "time_window_minutes": time_window_minutes,
                "vendors": vendors,
            },
        )

        logger.info(
            "situation_composer_runner.compose",
            session_id=session_id,
            time_window_minutes=time_window_minutes,
            vendors=vendors,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "situation_composer",
                    }
                },
            )
            final_state = SituationComposerState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "situation_composer_runner.completed",
                session_id=session_id,
                alerts=len(final_state.raw_alerts),
                correlations=len(final_state.correlations),
                has_situation=final_state.situation is not None,
                duration_ms=final_state.session_duration_ms,
            )

            return {
                "session_id": session_id,
                "situation": (
                    final_state.situation.model_dump() if final_state.situation else None
                ),
                "stats": final_state.stats,
                "reasoning_chain": [s.model_dump() for s in final_state.reasoning_chain],
                "error": final_state.error,
            }

        except Exception as e:
            logger.error(
                "situation_composer_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = SituationComposerState(
                request_id=session_id,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return {
                "session_id": session_id,
                "situation": None,
                "stats": {},
                "reasoning_chain": [],
                "error": str(e),
            }

    def get_result(self, session_id: str) -> SituationComposerState | None:
        """Retrieve a previous composition result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all composition results."""
        return [
            {
                "session_id": sid,
                "alerts": len(state.raw_alerts),
                "correlations": len(state.correlations),
                "has_situation": state.situation is not None,
                "current_step": state.current_step,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]

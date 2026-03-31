"""Security Gamification Engine Agent runner — entry point
for running security awareness gamification campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_gamification_engine.graph import (
    create_security_gamification_engine_graph,
)
from shieldops.agents.security_gamification_engine.models import (
    SecurityGamificationEngineState,
)
from shieldops.agents.security_gamification_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.security_gamification_engine.tools import (
    SecurityGamificationEngineToolkit,
)

logger = structlog.get_logger()


class SecurityGamificationEngineRunner:
    """Runner for the Security Gamification Engine Agent."""

    def __init__(
        self,
        challenge_store: Any | None = None,
        participation_tracker: Any | None = None,
        scoring_engine: Any | None = None,
        leaderboard_store: Any | None = None,
        badge_service: Any | None = None,
        metrics_store: Any | None = None,
        notification_service: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityGamificationEngineToolkit(
            challenge_store=challenge_store,
            participation_tracker=participation_tracker,
            scoring_engine=scoring_engine,
            leaderboard_store=leaderboard_store,
            badge_service=badge_service,
            metrics_store=metrics_store,
            notification_service=notification_service,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_gamification_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityGamificationEngineState] = {}
        logger.info("sge_runner.initialized")

    async def run_campaign(
        self,
        campaign_name: str,
        target_teams: list[str] | None = None,
        challenge_types: list[str] | None = None,
        config: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityGamificationEngineState:
        """Run a security gamification campaign."""
        request_id = f"sge-{uuid4().hex[:12]}"

        initial_state = SecurityGamificationEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            campaign_name=campaign_name,
            target_teams=target_teams or [],
            challenge_types=challenge_types or [],
            config=config or {},
        )

        logger.info(
            "sge_runner.starting",
            request_id=request_id,
            campaign=campaign_name,
            teams=len(target_teams or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_gamification_engine",
                    },
                },
            )
            final = SecurityGamificationEngineState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sge_runner.completed",
                request_id=request_id,
                participants=final.total_participants,
                avg_score=final.avg_score,
                badges=final.badges_awarded,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sge_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityGamificationEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                campaign_name=campaign_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityGamificationEngineState | None:
        """Retrieve a cached campaign result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all campaign results as summaries."""
        return [
            {
                "request_id": rid,
                "campaign": s.campaign_name,
                "participants": s.total_participants,
                "avg_score": s.avg_score,
                "completion_rate": s.completion_rate,
                "badges": s.badges_awarded,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]

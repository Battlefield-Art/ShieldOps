"""Situation Manager Agent runner."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.situation_manager.graph import (
    create_situation_manager_graph,
)
from shieldops.agents.situation_manager.models import (
    SituationManagerState,
)
from shieldops.agents.situation_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.situation_manager.tools import (
    SituationManagerToolkit,
)

logger = structlog.get_logger()


class SituationManagerRunner:
    """Runner for the Situation Manager Agent."""

    def __init__(
        self,
        alert_sources: Any | None = None,
        situation_store: Any | None = None,
        playbook_engine: Any | None = None,
        notification_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SituationManagerToolkit(
            alert_sources=alert_sources,
            situation_store=situation_store,
            playbook_engine=playbook_engine,
            notification_service=(notification_service),
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_situation_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, SituationManagerState] = {}
        logger.info("situation_manager_runner.initialized")

    async def manage(
        self,
        tenant_id: str,
        time_window_minutes: int = 60,
    ) -> SituationManagerState:
        """Run situation management pipeline."""
        session_id = f"sm-{uuid4().hex[:12]}"
        initial = SituationManagerState(
            tenant_id=tenant_id,
            time_window_minutes=time_window_minutes,
        )

        logger.info(
            "situation_manager.starting",
            session_id=session_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "situation_manager",
                    }
                },
            )
            final = SituationManagerState.model_validate(result)
            self._results[session_id] = final

            logger.info(
                "situation_manager.completed",
                session_id=session_id,
                alerts=(final.total_alerts_processed),
                situations=final.total_situations,
                auto_resolved=(final.auto_resolved_count),
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "situation_manager.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = SituationManagerState(
                tenant_id=tenant_id,
                error=str(e),
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> SituationManagerState | None:
        """Retrieve a stored result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all situation management summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "alerts": s.total_alerts_processed,
                "situations": s.total_situations,
                "auto_resolved": (s.auto_resolved_count),
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

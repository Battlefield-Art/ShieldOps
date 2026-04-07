"""Incident Replay Analyzer runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_replay_analyzer.graph import (
    create_incident_replay_analyzer_graph,
)
from shieldops.agents.incident_replay_analyzer.models import (
    IncidentReplayAnalyzerState,
)
from shieldops.agents.incident_replay_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.incident_replay_analyzer.tools import (
    IncidentReplayAnalyzerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentReplayAnalyzerRunner:
    """Runner for the Incident Replay Analyzer Agent."""

    def __init__(
        self,
        incident_store: Any | None = None,
        playbook_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IncidentReplayAnalyzerToolkit(
            incident_store=incident_store,
            playbook_engine=playbook_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_incident_replay_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentReplayAnalyzerState] = {}
        logger.info("ira_runner.initialized")

    @enforced("incident_replay_analyzer")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> IncidentReplayAnalyzerState:
        """Run incident replay workflow."""
        sid = f"ira-{uuid4().hex[:12]}"
        initial = IncidentReplayAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "ira_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "incident_replay_analyzer",
                    },
                },
            )
            final = IncidentReplayAnalyzerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "ira_runner.completed",
                session_id=sid,
                incidents=len(final.selected_incidents),
                playbooks=len(final.playbooks),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ira_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = IncidentReplayAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> IncidentReplayAnalyzerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "incidents": len(s.selected_incidents),
                "playbooks": len(s.playbooks),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]

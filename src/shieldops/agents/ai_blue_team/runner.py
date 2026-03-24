"""AI Blue Team Agent runner — entry point for defense hardening workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_blue_team.graph import create_ai_blue_team_graph
from shieldops.agents.ai_blue_team.models import AIBlueTeamState
from shieldops.agents.ai_blue_team.nodes import set_toolkit
from shieldops.agents.ai_blue_team.tools import AIBlueTeamToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.observability.tracing import get_tracer

if __import__("typing").TYPE_CHECKING:
    from shieldops.db.repository import Repository

logger = structlog.get_logger()


class AIBlueTeamRunner:
    """Runs AI blue team defense hardening workflows.

    Usage:
        runner = AIBlueTeamRunner(connector_router=router)
        result = await runner.harden(
            findings=[...],  # Red team findings
            context={"environment": "production", "scope": "network"},
        )
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: "Repository | None" = None,
    ) -> None:
        self._toolkit = AIBlueTeamToolkit(
            connector_router=connector_router,
            repository=repository,
        )
        set_toolkit(self._toolkit)

        graph = create_ai_blue_team_graph()
        self._app = graph.compile()

        self._sessions: dict[str, AIBlueTeamState] = {}
        self._repository = repository

    async def harden(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> AIBlueTeamState:
        """Run a full blue team hardening workflow from red team findings.

        Args:
            findings: Red team findings to respond to.
            context: Additional context (environment, scope, etc.).

        Returns:
            The completed AIBlueTeamState with hardening actions and detection rules.
        """
        session_id = f"blueteam-{uuid4().hex[:12]}"
        context = context or {}

        logger.info(
            "ai_blue_team_session_started",
            session_id=session_id,
            finding_count=len(findings),
        )

        initial_state = AIBlueTeamState(
            red_team_findings=findings,
            environment_context=context.get("environment_context", {}),
            hardening_scope=context.get("scope", "all"),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("ai_blue_team.harden") as span:
                span.set_attribute("ai_blue_team.session_id", session_id)
                span.set_attribute("ai_blue_team.finding_count", len(findings))

                final_state_dict = await self._app.ainvoke(  # type: ignore[arg-type]
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "session_id": session_id,
                        },
                    },
                )

                final_state = AIBlueTeamState.model_validate(final_state_dict)

                span.set_attribute(
                    "ai_blue_team.gaps_found",
                    len(final_state.gaps_identified),
                )
                span.set_attribute(
                    "ai_blue_team.actions_taken",
                    len(final_state.hardening_actions),
                )
                span.set_attribute(
                    "ai_blue_team.rules_created",
                    len(final_state.detection_rules_created),
                )

            logger.info(
                "ai_blue_team_session_completed",
                session_id=session_id,
                gaps=len(final_state.gaps_identified),
                actions=len(final_state.hardening_actions),
                rules=len(final_state.detection_rules_created),
                validations=len(final_state.validation_results),
                duration_ms=final_state.session_duration_ms,
            )

            self._sessions[session_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "ai_blue_team_session_failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = AIBlueTeamState(
                red_team_findings=findings,
                error=str(e),
                current_step="failed",
            )
            self._sessions[session_id] = error_state
            return error_state

    def get_session(self, session_id: str) -> AIBlueTeamState | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "status": state.current_step,
                "gaps": len(state.gaps_identified),
                "actions": len(state.hardening_actions),
                "rules": len(state.detection_rules_created),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for sid, state in self._sessions.items()
        ]

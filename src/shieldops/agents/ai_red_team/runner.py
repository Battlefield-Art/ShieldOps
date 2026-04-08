"""AI Red Team Agent runner — entry point for red team engagements."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_red_team.graph import create_ai_red_team_graph
from shieldops.agents.ai_red_team.models import AIRedTeamState
from shieldops.agents.ai_red_team.nodes import set_toolkit
from shieldops.agents.ai_red_team.tools import AIRedTeamToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AIRedTeamRunner:
    """Runs AI red team engagement workflows.

    Usage:
        runner = AIRedTeamRunner(connector_router=router)
        result = await runner.engage(
            target="production-cluster",
            objectives=["test_lateral_movement", "test_data_exfil"],
            context={"rules_of_engagement": {"no_destructive": True}},
        )
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AIRedTeamToolkit(
            connector_router=connector_router,
            repository=repository,
        )
        set_toolkit(self._toolkit)

        graph = create_ai_red_team_graph()
        self._app = graph.compile()

        self._engagements: dict[str, AIRedTeamState] = {}
        self._repository = repository

    async def engage(
        self,
        target: str,
        objectives: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> AIRedTeamState:
        """Run a full red team engagement against a target environment.

        Args:
            target: The target environment identifier.
            objectives: Attack objectives to pursue.
            context: Additional context (rules_of_engagement, mitre_techniques, etc.).

        Returns:
            The completed AIRedTeamState with findings and exploit chains.
        """
        engagement_id = f"redteam-{uuid4().hex[:12]}"
        context = context or {}
        objectives = objectives or ["test_defenses"]

        logger.info(
            "ai_red_team_engagement_started",
            engagement_id=engagement_id,
            target=target,
            objectives=objectives,
        )

        initial_state = AIRedTeamState(
            target_environment=target,
            attack_objectives=objectives,
            mitre_techniques=context.get(
                "mitre_techniques",
                [
                    "T1046",
                    "T1110.003",
                    "T1068",
                    "T1021",
                    "T1048",
                ],
            ),
            rules_of_engagement=context.get(
                "rules_of_engagement",
                {
                    "no_destructive": True,
                    "rate_limit": True,
                    "authorized_scope_only": True,
                },
            ),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("ai_red_team.engage") as span:
                span.set_attribute("ai_red_team.engagement_id", engagement_id)
                span.set_attribute("ai_red_team.target", target)

                final_state_dict = await self._app.ainvoke(  # type: ignore[arg-type]
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "engagement_id": engagement_id,
                            "target": target,
                        },
                    },
                )

                final_state = AIRedTeamState.model_validate(final_state_dict)

                span.set_attribute(
                    "ai_red_team.vulns_found",
                    len(final_state.vulnerabilities_found),
                )
                span.set_attribute(
                    "ai_red_team.chains_found",
                    len(final_state.exploit_chains),
                )

            logger.info(
                "ai_red_team_engagement_completed",
                engagement_id=engagement_id,
                target=target,
                scenarios=len(final_state.attack_scenarios_generated),
                probes=len(final_state.probes_executed),
                vulns=len(final_state.vulnerabilities_found),
                chains=len(final_state.exploit_chains),
                duration_ms=final_state.session_duration_ms,
            )

            self._engagements[engagement_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "ai_red_team_engagement_failed",
                engagement_id=engagement_id,
                target=target,
                error=str(e),
            )
            error_state = AIRedTeamState(
                target_environment=target,
                error=str(e),
                current_step="failed",
            )
            self._engagements[engagement_id] = error_state
            return error_state

    def get_engagement(self, engagement_id: str) -> AIRedTeamState | None:
        return self._engagements.get(engagement_id)

    def list_engagements(self) -> list[dict[str, Any]]:
        return [
            {
                "engagement_id": eid,
                "target": state.target_environment,
                "status": state.current_step,
                "scenarios": len(state.attack_scenarios_generated),
                "vulns": len(state.vulnerabilities_found),
                "chains": len(state.exploit_chains),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for eid, state in self._engagements.items()
        ]

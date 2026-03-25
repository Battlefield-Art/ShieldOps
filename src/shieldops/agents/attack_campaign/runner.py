"""Attack Campaign Agent runner — entry point for campaign execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_campaign.graph import create_attack_campaign_graph
from shieldops.agents.attack_campaign.models import (
    AttackCampaignState,
    SimulationMode,
)
from shieldops.agents.attack_campaign.nodes import set_toolkit
from shieldops.agents.attack_campaign.tools import AttackCampaignToolkit
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AttackCampaignRunner:
    """Runs multi-step attack campaign simulations.

    Usage:
        runner = AttackCampaignRunner()
        result = await runner.run_campaign(
            campaign_name="Q1 Adversary Emulation",
            target_scope={"target": "prod-cluster", "platforms": ["linux", "kubernetes"]},
            simulation_mode="dry_run",
        )
    """

    def __init__(
        self,
        mitre_client: Any | None = None,
        simulation_engine: Any | None = None,
        defense_monitor: Any | None = None,
    ) -> None:
        self._toolkit = AttackCampaignToolkit(
            mitre_client=mitre_client,
            simulation_engine=simulation_engine,
            defense_monitor=defense_monitor,
        )
        set_toolkit(self._toolkit)

        graph = create_attack_campaign_graph(
            mitre_client=mitre_client,
            simulation_engine=simulation_engine,
            defense_monitor=defense_monitor,
        )
        self._app = graph.compile()

        self._campaigns: dict[str, AttackCampaignState] = {}

    async def run_campaign(
        self,
        campaign_name: str,
        target_scope: dict[str, Any] | None = None,
        simulation_mode: str = "dry_run",
    ) -> dict[str, Any]:
        """Run a full attack campaign simulation.

        Args:
            campaign_name: Human-readable campaign name.
            target_scope: Target environment description
                (platforms, target, phases, max_severity, etc.).
            simulation_mode: One of dry_run, read_only, controlled, full.
                Defaults to dry_run for safety.

        Returns:
            Dict with campaign_id, campaign_result, reasoning_chain, and metadata.
        """
        campaign_id = f"campaign-{uuid4().hex[:12]}"
        target_scope = target_scope or {
            "target": "default-environment",
            "platforms": ["linux", "cloud"],
        }

        # Validate and default to DRY_RUN for safety
        try:
            mode = SimulationMode(simulation_mode)
        except ValueError:
            logger.warning(
                "attack_campaign.invalid_mode",
                requested=simulation_mode,
                defaulting_to="dry_run",
            )
            mode = SimulationMode.DRY_RUN

        logger.info(
            "attack_campaign_started",
            campaign_id=campaign_id,
            campaign_name=campaign_name,
            mode=mode,
            target_scope=target_scope,
        )

        initial_state = AttackCampaignState(
            request_id=f"req-{uuid4().hex[:8]}",
            campaign_id=campaign_id,
            campaign_name=campaign_name,
            target_scope=target_scope,
            simulation_mode=mode,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("attack_campaign.run") as span:
                span.set_attribute("attack_campaign.campaign_id", campaign_id)
                span.set_attribute("attack_campaign.mode", mode.value)
                span.set_attribute("attack_campaign.name", campaign_name)

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "campaign_id": campaign_id,
                            "campaign_name": campaign_name,
                        },
                    },
                )

                final_state = AttackCampaignState.model_validate(final_state_dict)

                span.set_attribute(
                    "attack_campaign.total_steps",
                    len(final_state.simulation_steps),
                )
                if final_state.campaign_result:
                    span.set_attribute(
                        "attack_campaign.detection_rate",
                        final_state.campaign_result.detection_rate,
                    )

            logger.info(
                "attack_campaign_completed",
                campaign_id=campaign_id,
                campaign_name=campaign_name,
                ttps=len(final_state.ttp_selections),
                steps=len(final_state.simulation_steps),
                assessments=len(final_state.defense_assessments),
                duration_ms=final_state.session_duration_ms,
            )

            self._campaigns[campaign_id] = final_state

            return {
                "campaign_id": campaign_id,
                "campaign_name": campaign_name,
                "simulation_mode": mode.value,
                "ttp_count": len(final_state.ttp_selections),
                "steps_executed": len(final_state.simulation_steps),
                "campaign_result": (
                    final_state.campaign_result.model_dump()
                    if final_state.campaign_result
                    else None
                ),
                "defense_assessments": [a.model_dump() for a in final_state.defense_assessments],
                "reasoning_chain": [r.model_dump() for r in final_state.reasoning_chain],
                "duration_ms": final_state.session_duration_ms,
                "error": final_state.error,
            }

        except Exception as e:
            logger.error(
                "attack_campaign_failed",
                campaign_id=campaign_id,
                error=str(e),
            )
            error_state = AttackCampaignState(
                campaign_id=campaign_id,
                campaign_name=campaign_name,
                error=str(e),
                current_step="failed",
            )
            self._campaigns[campaign_id] = error_state
            return {
                "campaign_id": campaign_id,
                "campaign_name": campaign_name,
                "error": str(e),
            }

    def get_campaign(self, campaign_id: str) -> AttackCampaignState | None:
        """Retrieve a completed campaign state by ID."""
        return self._campaigns.get(campaign_id)

    def list_campaigns(self) -> list[dict[str, Any]]:
        """List all campaigns run by this runner instance."""
        return [
            {
                "campaign_id": cid,
                "campaign_name": state.campaign_name,
                "mode": state.simulation_mode.value,
                "status": state.current_step,
                "ttps": len(state.ttp_selections),
                "steps": len(state.simulation_steps),
                "result": (state.campaign_result.model_dump() if state.campaign_result else None),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for cid, state in self._campaigns.items()
        ]

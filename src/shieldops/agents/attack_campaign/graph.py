"""LangGraph workflow definition for the Attack Campaign Agent."""

from __future__ import annotations

from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.attack_campaign.models import AttackCampaignState
from shieldops.agents.attack_campaign.nodes import (
    assess_defenses,
    collect_results,
    execute_simulation,
    generate_report,
    plan_campaign,
    select_ttps,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def create_attack_campaign_graph(
    mitre_client: Any | None = None,
    simulation_engine: Any | None = None,
    defense_monitor: Any | None = None,
) -> StateGraph[AttackCampaignState]:
    """Build the Attack Campaign Agent LangGraph workflow.

    Workflow:
        plan_campaign → select_ttps → execute_simulation
            → collect_results → assess_defenses → generate_report → END

    Args:
        mitre_client: Optional MITRE ATT&CK API client.
        simulation_engine: Optional simulation execution engine.
        defense_monitor: Optional defense telemetry monitor.
    """
    # If dependencies are supplied, configure the toolkit before graph runs
    if any([mitre_client, simulation_engine, defense_monitor]):
        from shieldops.agents.attack_campaign.nodes import set_toolkit
        from shieldops.agents.attack_campaign.tools import AttackCampaignToolkit

        toolkit = AttackCampaignToolkit(
            mitre_client=mitre_client,
            simulation_engine=simulation_engine,
            defense_monitor=defense_monitor,
        )
        set_toolkit(toolkit)

    graph = StateGraph(AttackCampaignState)

    _agent = "attack_campaign"
    graph.add_node(
        "plan_campaign",
        traced_node("attack_campaign.plan_campaign", _agent)(plan_campaign),
    )
    graph.add_node(
        "select_ttps",
        traced_node("attack_campaign.select_ttps", _agent)(select_ttps),
    )
    graph.add_node(
        "execute_simulation",
        traced_node("attack_campaign.execute_simulation", _agent)(execute_simulation),
    )
    graph.add_node(
        "collect_results",
        traced_node("attack_campaign.collect_results", _agent)(collect_results),
    )
    graph.add_node(
        "assess_defenses",
        traced_node("attack_campaign.assess_defenses", _agent)(assess_defenses),
    )
    graph.add_node(
        "generate_report",
        traced_node("attack_campaign.generate_report", _agent)(generate_report),
    )

    # Define edges — linear pipeline
    graph.set_entry_point("plan_campaign")
    graph.add_edge("plan_campaign", "select_ttps")
    graph.add_edge("select_ttps", "execute_simulation")
    graph.add_edge("execute_simulation", "collect_results")
    graph.add_edge("collect_results", "assess_defenses")
    graph.add_edge("assess_defenses", "generate_report")
    graph.add_edge("generate_report", END)

    return graph

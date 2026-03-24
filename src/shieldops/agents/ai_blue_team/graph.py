"""LangGraph workflow definition for the AI Blue Team Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.ai_blue_team.models import AIBlueTeamState
from shieldops.agents.ai_blue_team.nodes import (
    analyze_findings,
    apply_hardening,
    create_detection_rules,
    generate_hardening_plan,
    identify_gaps,
    validate,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def create_ai_blue_team_graph() -> StateGraph[AIBlueTeamState]:
    """Build the AI Blue Team Agent LangGraph workflow.

    Workflow:
        analyze_findings → identify_gaps → generate_hardening_plan
            → apply_hardening → create_detection_rules → validate → END
    """
    graph = StateGraph(AIBlueTeamState)

    _agent = "ai_blue_team"
    graph.add_node(
        "analyze_findings",
        traced_node("ai_blue_team.analyze_findings", _agent)(analyze_findings),
    )
    graph.add_node(
        "identify_gaps",
        traced_node("ai_blue_team.identify_gaps", _agent)(identify_gaps),
    )
    graph.add_node(
        "generate_hardening_plan",
        traced_node("ai_blue_team.generate_hardening_plan", _agent)(generate_hardening_plan),
    )
    graph.add_node(
        "apply_hardening",
        traced_node("ai_blue_team.apply_hardening", _agent)(apply_hardening),
    )
    graph.add_node(
        "create_detection_rules",
        traced_node("ai_blue_team.create_detection_rules", _agent)(create_detection_rules),
    )
    graph.add_node(
        "validate",
        traced_node("ai_blue_team.validate", _agent)(validate),
    )

    # Define edges — linear pipeline
    graph.set_entry_point("analyze_findings")
    graph.add_edge("analyze_findings", "identify_gaps")
    graph.add_edge("identify_gaps", "generate_hardening_plan")
    graph.add_edge("generate_hardening_plan", "apply_hardening")
    graph.add_edge("apply_hardening", "create_detection_rules")
    graph.add_edge("create_detection_rules", "validate")
    graph.add_edge("validate", END)

    return graph

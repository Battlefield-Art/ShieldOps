"""LangGraph workflow definition for the AI Red Team Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.ai_red_team.models import AIRedTeamState
from shieldops.agents.ai_red_team.nodes import (
    analyze_results,
    chain_exploits,
    execute_probes,
    generate_findings,
    generate_scenarios,
    select_techniques,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_chain_exploits(state: AIRedTeamState) -> str:
    """Route based on whether vulnerabilities were found."""
    if state.error:
        return "generate_findings"
    if state.vulnerabilities_found:
        return "chain_exploits"
    return "generate_findings"


def create_ai_red_team_graph() -> StateGraph[AIRedTeamState]:
    """Build the AI Red Team Agent LangGraph workflow.

    Workflow:
        generate_scenarios → select_techniques → execute_probes
            → analyze_results → [conditional: chain_exploits OR generate_findings]
            → generate_findings → END
    """
    graph = StateGraph(AIRedTeamState)

    _agent = "ai_red_team"
    graph.add_node(
        "generate_scenarios",
        traced_node("ai_red_team.generate_scenarios", _agent)(generate_scenarios),
    )
    graph.add_node(
        "select_techniques",
        traced_node("ai_red_team.select_techniques", _agent)(select_techniques),
    )
    graph.add_node(
        "execute_probes",
        traced_node("ai_red_team.execute_probes", _agent)(execute_probes),
    )
    graph.add_node(
        "analyze_results",
        traced_node("ai_red_team.analyze_results", _agent)(analyze_results),
    )
    graph.add_node(
        "chain_exploits",
        traced_node("ai_red_team.chain_exploits", _agent)(chain_exploits),
    )
    graph.add_node(
        "generate_findings",
        traced_node("ai_red_team.generate_findings", _agent)(generate_findings),
    )

    # Define edges
    graph.set_entry_point("generate_scenarios")
    graph.add_edge("generate_scenarios", "select_techniques")
    graph.add_edge("select_techniques", "execute_probes")
    graph.add_edge("execute_probes", "analyze_results")
    graph.add_conditional_edges(
        "analyze_results",
        should_chain_exploits,
        {
            "chain_exploits": "chain_exploits",
            "generate_findings": "generate_findings",
        },
    )
    graph.add_edge("chain_exploits", "generate_findings")
    graph.add_edge("generate_findings", END)

    return graph

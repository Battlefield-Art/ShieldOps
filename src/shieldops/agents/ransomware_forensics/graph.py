"""LangGraph workflow definition for the Ransomware Forensics Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.ransomware_forensics.models import (
    RansomwareForensicsState,
)
from shieldops.agents.ransomware_forensics.nodes import (
    analyze_attack_chain,
    assess_blast_radius,
    collect_artifacts,
    generate_report,
    identify_variant,
    recommend_recovery,
)
from shieldops.agents.tracing import traced_node


def should_continue_after_blast(
    state: RansomwareForensicsState,
) -> str:
    """Route based on blast radius severity."""
    if state.error:
        return "generate_report"

    level = state.blast_radius.get("level", "")
    if level == "catastrophic":
        # Skip recovery planning, escalate immediately
        return "generate_report"
    return "recommend_recovery"


def create_ransomware_forensics_graph() -> StateGraph[RansomwareForensicsState]:
    """Build the Ransomware Forensics LangGraph workflow.

    Workflow:
        collect_artifacts → analyze_attack_chain
            → identify_variant → assess_blast_radius
            → [catastrophic? → generate_report]
            → [else → recommend_recovery → generate_report]
            → END
    """
    graph = StateGraph(RansomwareForensicsState)

    _agent = "ransomware_forensics"
    graph.add_node(
        "collect_artifacts",
        traced_node(
            "ransomware_forensics.collect_artifacts",
            _agent,
        )(collect_artifacts),
    )
    graph.add_node(
        "analyze_attack_chain",
        traced_node(
            "ransomware_forensics.analyze_attack_chain",
            _agent,
        )(analyze_attack_chain),
    )
    graph.add_node(
        "identify_variant",
        traced_node(
            "ransomware_forensics.identify_variant",
            _agent,
        )(identify_variant),
    )
    graph.add_node(
        "assess_blast_radius",
        traced_node(
            "ransomware_forensics.assess_blast_radius",
            _agent,
        )(assess_blast_radius),
    )
    graph.add_node(
        "recommend_recovery",
        traced_node(
            "ransomware_forensics.recommend_recovery",
            _agent,
        )(recommend_recovery),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "ransomware_forensics.generate_report",
            _agent,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_artifacts")
    graph.add_edge("collect_artifacts", "analyze_attack_chain")
    graph.add_edge("analyze_attack_chain", "identify_variant")
    graph.add_edge("identify_variant", "assess_blast_radius")
    graph.add_conditional_edges(
        "assess_blast_radius",
        should_continue_after_blast,
        {
            "recommend_recovery": "recommend_recovery",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_recovery", "generate_report")
    graph.add_edge("generate_report", END)

    return graph

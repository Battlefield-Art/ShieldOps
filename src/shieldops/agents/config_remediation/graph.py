"""LangGraph workflow for the Config Remediation Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.config_remediation.models import (
    ConfigRemediationState,
)
from shieldops.agents.config_remediation.nodes import (
    apply_fixes,
    generate_fixes,
    generate_report,
    identify_misconfigs,
    scan_configurations,
    verify_fixes,
)
from shieldops.agents.tracing import traced_node


def build_graph() -> StateGraph:
    """Build the Config Remediation LangGraph."""
    _a = "config_remediation"
    graph = StateGraph(ConfigRemediationState)

    graph.add_node(
        "scan_configurations",
        traced_node("cfgrem.scan", _a)(scan_configurations),
    )
    graph.add_node(
        "identify_misconfigs",
        traced_node("cfgrem.identify", _a)(identify_misconfigs),
    )
    graph.add_node(
        "generate_fixes",
        traced_node("cfgrem.generate", _a)(generate_fixes),
    )
    graph.add_node(
        "apply_fixes",
        traced_node("cfgrem.apply", _a)(apply_fixes),
    )
    graph.add_node(
        "verify_fixes",
        traced_node("cfgrem.verify", _a)(verify_fixes),
    )
    graph.add_node(
        "generate_report",
        traced_node("cfgrem.report", _a)(generate_report),
    )

    graph.set_entry_point("scan_configurations")
    graph.add_edge("scan_configurations", "identify_misconfigs")
    graph.add_edge("identify_misconfigs", "generate_fixes")
    graph.add_edge("generate_fixes", "apply_fixes")
    graph.add_edge("apply_fixes", "verify_fixes")
    graph.add_edge("verify_fixes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_config_remediation_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create a Config Remediation graph."""
    return build_graph()

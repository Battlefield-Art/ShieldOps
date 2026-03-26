"""LangGraph workflow definition for Exposure Management."""

from langgraph.graph import END, StateGraph

from shieldops.agents.exposure_management.models import (
    ExposureManagementState,
)
from shieldops.agents.exposure_management.nodes import (
    assess_exposures,
    discover_attack_surface,
    enumerate_assets,
    prioritize_risks,
    recommend_remediation,
    report,
)
from shieldops.agents.tracing import traced_node

# ── Routing Functions ───────────────────────────────────


def should_enumerate(
    state: ExposureManagementState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "report"
    if state.surface_count > 0:
        return "enumerate_assets"
    return "report"


def should_assess(
    state: ExposureManagementState,
) -> str:
    """Route after enumeration based on asset count."""
    if state.asset_count > 0:
        return "assess_exposures"
    return "report"


def should_remediate(
    state: ExposureManagementState,
) -> str:
    """Route after prioritization based on severity."""
    if state.critical_count > 0:
        return "recommend_remediation"
    return "report"


# ── Graph Builder ───────────────────────────────────────


def create_exposure_management_graph() -> StateGraph[ExposureManagementState]:
    """Build the Exposure Management LangGraph workflow.

    Workflow:
        discover_attack_surface
          -> [has_surfaces? -> enumerate_assets]
          -> [has_assets? -> assess_exposures]
          -> prioritize_risks
          -> [critical? -> recommend_remediation]
          -> report
    """
    graph = StateGraph(ExposureManagementState)

    _agent = "exposure_management"
    graph.add_node(
        "discover_attack_surface",
        traced_node(
            "exposure_mgmt.discover_attack_surface",
            _agent,
        )(discover_attack_surface),
    )
    graph.add_node(
        "enumerate_assets",
        traced_node(
            "exposure_mgmt.enumerate_assets",
            _agent,
        )(enumerate_assets),
    )
    graph.add_node(
        "assess_exposures",
        traced_node(
            "exposure_mgmt.assess_exposures",
            _agent,
        )(assess_exposures),
    )
    graph.add_node(
        "prioritize_risks",
        traced_node(
            "exposure_mgmt.prioritize_risks",
            _agent,
        )(prioritize_risks),
    )
    graph.add_node(
        "recommend_remediation",
        traced_node(
            "exposure_mgmt.recommend_remediation",
            _agent,
        )(recommend_remediation),
    )
    graph.add_node(
        "report",
        traced_node(
            "exposure_mgmt.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("discover_attack_surface")
    graph.add_conditional_edges(
        "discover_attack_surface",
        should_enumerate,
        {
            "enumerate_assets": "enumerate_assets",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "enumerate_assets",
        should_assess,
        {
            "assess_exposures": "assess_exposures",
            "report": "report",
        },
    )
    graph.add_edge("assess_exposures", "prioritize_risks")
    graph.add_conditional_edges(
        "prioritize_risks",
        should_remediate,
        {
            "recommend_remediation": ("recommend_remediation"),
            "report": "report",
        },
    )
    graph.add_edge("recommend_remediation", "report")
    graph.add_edge("report", END)

    return graph

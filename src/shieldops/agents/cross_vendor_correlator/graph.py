"""LangGraph workflow for the Cross-Vendor Correlator Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.cross_vendor_correlator.models import (
    CrossVendorCorrelatorState,
)
from shieldops.agents.cross_vendor_correlator.nodes import (
    build_kill_chain,
    correlate_by_entity,
    create_situations,
    generate_report,
    ingest_vendor_alerts,
    normalize_to_ocsf,
)
from shieldops.agents.tracing import traced_node

_AGENT = "cross_vendor_correlator"


def _has_alerts(
    state: CrossVendorCorrelatorState,
) -> str:
    """Route based on whether alerts were ingested."""
    if state.error:
        return END
    if not state.vendor_alerts:
        return "generate_report"
    return "normalize_to_ocsf"


def _has_correlations(
    state: CrossVendorCorrelatorState,
) -> str:
    """Route based on whether correlations exist."""
    if state.error:
        return END
    if not state.correlations:
        return "generate_report"
    return "build_kill_chain"


def create_cross_vendor_correlator_graph() -> StateGraph:
    """Build the Cross-Vendor Correlator workflow.

    Workflow:
        ingest_vendor_alerts
            -> [no alerts? -> generate_report -> END]
            -> normalize_to_ocsf
            -> correlate_by_entity
            -> [no correlations? -> report -> END]
            -> build_kill_chain
            -> create_situations
            -> generate_report -> END
    """
    graph = StateGraph(CrossVendorCorrelatorState)

    graph.add_node(
        "ingest_vendor_alerts",
        traced_node(
            "cross_vendor.ingest_vendor_alerts",
            _AGENT,
        )(ingest_vendor_alerts),
    )
    graph.add_node(
        "normalize_to_ocsf",
        traced_node(
            "cross_vendor.normalize_to_ocsf",
            _AGENT,
        )(normalize_to_ocsf),
    )
    graph.add_node(
        "correlate_by_entity",
        traced_node(
            "cross_vendor.correlate_by_entity",
            _AGENT,
        )(correlate_by_entity),
    )
    graph.add_node(
        "build_kill_chain",
        traced_node(
            "cross_vendor.build_kill_chain",
            _AGENT,
        )(build_kill_chain),
    )
    graph.add_node(
        "create_situations",
        traced_node(
            "cross_vendor.create_situations",
            _AGENT,
        )(create_situations),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "cross_vendor.generate_report",
            _AGENT,
        )(generate_report),
    )

    graph.set_entry_point("ingest_vendor_alerts")
    graph.add_conditional_edges(
        "ingest_vendor_alerts",
        _has_alerts,
        {
            "normalize_to_ocsf": "normalize_to_ocsf",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("normalize_to_ocsf", "correlate_by_entity")
    graph.add_conditional_edges(
        "correlate_by_entity",
        _has_correlations,
        {
            "build_kill_chain": "build_kill_chain",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("build_kill_chain", "create_situations")
    graph.add_edge("create_situations", "generate_report")
    graph.add_edge("generate_report", END)

    return graph

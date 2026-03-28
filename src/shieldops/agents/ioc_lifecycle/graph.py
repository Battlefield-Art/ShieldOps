"""LangGraph workflow definition for the IOC Lifecycle Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.ioc_lifecycle.models import (
    IOCLifecycleState,
)
from shieldops.agents.ioc_lifecycle.nodes import (
    age_check,
    classify,
    collect,
    enrich,
    report,
    validate,
)
from shieldops.agents.tracing import traced_node


def _should_continue(
    state: IOCLifecycleState,
) -> str:
    """Route to report on error, otherwise continue."""
    if state.error:
        return "report"
    return "continue"


def create_ioc_lifecycle_graph() -> StateGraph[IOCLifecycleState]:
    """Build the IOC Lifecycle LangGraph workflow.

    Workflow:
        collect -> validate -> enrich -> classify
            -> age_check -> report -> END
        Any error routes directly to report.
    """
    graph = StateGraph(IOCLifecycleState)

    _agent = "ioc_lifecycle"
    graph.add_node(
        "collect",
        traced_node(
            "ioc_lifecycle.collect",
            _agent,
        )(collect),
    )
    graph.add_node(
        "validate",
        traced_node(
            "ioc_lifecycle.validate",
            _agent,
        )(validate),
    )
    graph.add_node(
        "enrich",
        traced_node(
            "ioc_lifecycle.enrich",
            _agent,
        )(enrich),
    )
    graph.add_node(
        "classify",
        traced_node(
            "ioc_lifecycle.classify",
            _agent,
        )(classify),
    )
    graph.add_node(
        "age_check",
        traced_node(
            "ioc_lifecycle.age_check",
            _agent,
        )(age_check),
    )
    graph.add_node(
        "report",
        traced_node(
            "ioc_lifecycle.report",
            _agent,
        )(report),
    )

    # Entry point
    graph.set_entry_point("collect")

    # Linear flow with error routing
    graph.add_conditional_edges(
        "collect",
        _should_continue,
        {
            "continue": "validate",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "validate",
        _should_continue,
        {
            "continue": "enrich",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "enrich",
        _should_continue,
        {
            "continue": "classify",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "classify",
        _should_continue,
        {
            "continue": "age_check",
            "report": "report",
        },
    )
    graph.add_conditional_edges(
        "age_check",
        _should_continue,
        {
            "continue": "report",
            "report": "report",
        },
    )
    graph.add_edge("report", END)

    return graph

"""LangGraph workflow for the Security Workflow Optimizer Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_workflow_optimizer.models import (
    SecurityWorkflowOptimizerState,
)
from shieldops.agents.security_workflow_optimizer.nodes import (
    analyze_patterns,
    collect_workflows,
    generate_report,
    identify_bottlenecks,
    optimize_paths,
    validate_improvements,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_workflow_optimizer"


def _should_optimize(
    state: SecurityWorkflowOptimizerState,
) -> str:
    """Route after bottleneck identification."""
    if state.error:
        return "generate_report"
    if state.bottlenecks:
        return "optimize_paths"
    return "generate_report"


def _should_validate(
    state: SecurityWorkflowOptimizerState,
) -> str:
    """Route after optimization."""
    if state.optimizations:
        return "validate_improvements"
    return "generate_report"


def create_security_workflow_optimizer_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Workflow Optimizer LangGraph.

    Workflow:
        collect_workflows -> analyze_patterns
          -> identify_bottlenecks
          -> [has_bottlenecks?] -> optimize_paths
          -> [has_optimizations?] -> validate_improvements
          -> generate_report
    """
    graph = StateGraph(SecurityWorkflowOptimizerState)

    graph.add_node(
        "collect_workflows",
        traced_node(f"{_AGENT}.collect_workflows", _AGENT)(collect_workflows),
    )
    graph.add_node(
        "analyze_patterns",
        traced_node(f"{_AGENT}.analyze_patterns", _AGENT)(analyze_patterns),
    )
    graph.add_node(
        "identify_bottlenecks",
        traced_node(f"{_AGENT}.identify_bottlenecks", _AGENT)(identify_bottlenecks),
    )
    graph.add_node(
        "optimize_paths",
        traced_node(f"{_AGENT}.optimize_paths", _AGENT)(optimize_paths),
    )
    graph.add_node(
        "validate_improvements",
        traced_node(f"{_AGENT}.validate_improvements", _AGENT)(validate_improvements),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("collect_workflows")
    graph.add_edge("collect_workflows", "analyze_patterns")
    graph.add_edge("analyze_patterns", "identify_bottlenecks")
    graph.add_conditional_edges(
        "identify_bottlenecks",
        _should_optimize,
        {
            "optimize_paths": "optimize_paths",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "optimize_paths",
        _should_validate,
        {
            "validate_improvements": "validate_improvements",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_improvements", "generate_report")
    graph.add_edge("generate_report", END)

    return graph

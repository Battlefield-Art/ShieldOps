"""LangGraph workflow for the Security Automation Pipeline Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_automation_pipeline.models import (
    SecurityAutomationPipelineState,
)
from shieldops.agents.security_automation_pipeline.nodes import (
    enforce_gates,
    evaluate_results,
    generate_report,
    inject_gates,
    run_checks,
    scan_pipeline,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_automation_pipeline"


def _should_inject(
    state: SecurityAutomationPipelineState,
) -> str:
    """Route after scanning based on results."""
    if state.error:
        return "generate_report"
    if state.pipeline_scans:
        return "inject_gates"
    return "generate_report"


def _should_enforce(
    state: SecurityAutomationPipelineState,
) -> str:
    """Route after evaluation."""
    if state.gates_failed > 0:
        return "enforce_gates"
    return "generate_report"


def create_security_automation_pipeline_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Automation Pipeline LangGraph.

    Workflow:
        scan_pipeline
          -> [has_pipelines?] -> inject_gates
          -> run_checks
          -> evaluate_results
          -> [has_failures?] -> enforce_gates
          -> generate_report
    """
    graph = StateGraph(SecurityAutomationPipelineState)

    graph.add_node(
        "scan_pipeline",
        traced_node(
            f"{_AGENT}.scan_pipeline",
            _AGENT,
        )(scan_pipeline),
    )
    graph.add_node(
        "inject_gates",
        traced_node(
            f"{_AGENT}.inject_gates",
            _AGENT,
        )(inject_gates),
    )
    graph.add_node(
        "run_checks",
        traced_node(
            f"{_AGENT}.run_checks",
            _AGENT,
        )(run_checks),
    )
    graph.add_node(
        "evaluate_results",
        traced_node(
            f"{_AGENT}.evaluate_results",
            _AGENT,
        )(evaluate_results),
    )
    graph.add_node(
        "enforce_gates",
        traced_node(
            f"{_AGENT}.enforce_gates",
            _AGENT,
        )(enforce_gates),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("scan_pipeline")
    graph.add_conditional_edges(
        "scan_pipeline",
        _should_inject,
        {
            "inject_gates": "inject_gates",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("inject_gates", "run_checks")
    graph.add_edge("run_checks", "evaluate_results")
    graph.add_conditional_edges(
        "evaluate_results",
        _should_enforce,
        {
            "enforce_gates": "enforce_gates",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("enforce_gates", "generate_report")
    graph.add_edge("generate_report", END)

    return graph

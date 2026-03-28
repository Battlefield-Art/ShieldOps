"""LangGraph workflow for the Security Pipeline Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.security_pipeline.models import (
    SecurityPipelineState,
)
from shieldops.agents.security_pipeline.nodes import (
    collect_findings,
    dispatch_discovery,
    dispatch_pentest,
    dispatch_remediation,
    generate_report,
    plan_pipeline,
    verify_results,
)
from shieldops.agents.tracing import traced_node

_AGENT = "security_pipeline"


def _has_findings(
    state: SecurityPipelineState,
) -> str:
    """Route based on whether findings exist."""
    if state.error:
        return END
    if not state.findings:
        return "generate_report"
    return "dispatch_remediation"


def build_graph(
    toolkit: object | None = None,
) -> StateGraph:
    """Build the Security Pipeline StateGraph.

    Workflow:
        plan_pipeline -> dispatch_discovery
        -> dispatch_pentest -> collect_findings
        -> [no findings? -> generate_report -> END]
        -> dispatch_remediation -> verify_results
        -> generate_report -> END
    """
    graph = StateGraph(SecurityPipelineState)

    graph.add_node(
        "plan_pipeline",
        traced_node(f"{_AGENT}.plan_pipeline", _AGENT)(plan_pipeline),
    )
    graph.add_node(
        "dispatch_discovery",
        traced_node(f"{_AGENT}.dispatch_discovery", _AGENT)(dispatch_discovery),
    )
    graph.add_node(
        "dispatch_pentest",
        traced_node(f"{_AGENT}.dispatch_pentest", _AGENT)(dispatch_pentest),
    )
    graph.add_node(
        "collect_findings",
        traced_node(f"{_AGENT}.collect_findings", _AGENT)(collect_findings),
    )
    graph.add_node(
        "dispatch_remediation",
        traced_node(f"{_AGENT}.dispatch_remediation", _AGENT)(dispatch_remediation),
    )
    graph.add_node(
        "verify_results",
        traced_node(f"{_AGENT}.verify_results", _AGENT)(verify_results),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(generate_report),
    )

    graph.set_entry_point("plan_pipeline")
    graph.add_edge("plan_pipeline", "dispatch_discovery")
    graph.add_edge("dispatch_discovery", "dispatch_pentest")
    graph.add_edge("dispatch_pentest", "collect_findings")
    graph.add_conditional_edges(
        "collect_findings",
        _has_findings,
        {
            "dispatch_remediation": ("dispatch_remediation"),
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("dispatch_remediation", "verify_results")
    graph.add_edge("verify_results", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_security_pipeline_graph(
    **clients: object,
) -> StateGraph:
    """Factory to create the Security Pipeline graph."""
    return build_graph()

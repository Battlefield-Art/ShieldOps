"""LangGraph workflow definition for the Adversarial Validation Agent."""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.adversarial_validation.models import (
    AdversarialValidationState,
)
from shieldops.agents.adversarial_validation.nodes import (
    assess_effectiveness,
    collect_findings,
    execute_validation,
    report,
    select_retests,
    update_patterns,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_update_patterns(state: AdversarialValidationState) -> str:
    """Route based on whether regressions were found.

    If regressions exist the flywheel must update attack/defense patterns
    before generating the final report. Otherwise skip straight to report.
    """
    if state.error:
        return "report"
    if state.regressions_found > 0:
        return "update_patterns"
    return "report"


def create_adversarial_validation_graph() -> StateGraph[AdversarialValidationState]:
    """Build the Adversarial Validation Agent LangGraph workflow.

    Workflow::

        collect_findings → select_retests → execute_validation
            → assess_effectiveness
            → [conditional: regressions → update_patterns → report]
            → [conditional: no regressions → report]
            → END
    """
    graph = StateGraph(AdversarialValidationState)

    _agent = "adversarial_validation"
    graph.add_node(
        "collect_findings",
        traced_node("adversarial_validation.collect_findings", _agent)(collect_findings),
    )
    graph.add_node(
        "select_retests",
        traced_node("adversarial_validation.select_retests", _agent)(select_retests),
    )
    graph.add_node(
        "execute_validation",
        traced_node("adversarial_validation.execute_validation", _agent)(execute_validation),
    )
    graph.add_node(
        "assess_effectiveness",
        traced_node("adversarial_validation.assess_effectiveness", _agent)(assess_effectiveness),
    )
    graph.add_node(
        "update_patterns",
        traced_node("adversarial_validation.update_patterns", _agent)(update_patterns),
    )
    graph.add_node(
        "report",
        traced_node("adversarial_validation.report", _agent)(report),
    )

    # Linear flow with conditional branch after assess_effectiveness
    graph.set_entry_point("collect_findings")
    graph.add_edge("collect_findings", "select_retests")
    graph.add_edge("select_retests", "execute_validation")
    graph.add_edge("execute_validation", "assess_effectiveness")
    graph.add_conditional_edges(
        "assess_effectiveness",
        should_update_patterns,
        {
            "update_patterns": "update_patterns",
            "report": "report",
        },
    )
    graph.add_edge("update_patterns", "report")
    graph.add_edge("report", END)

    return graph

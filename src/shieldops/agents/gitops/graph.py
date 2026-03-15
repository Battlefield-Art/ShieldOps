"""LangGraph workflow definition for the GitOps Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.gitops.models import GitOpsState
from shieldops.agents.gitops.nodes import (
    apply_reconciliation,
    detect_drift,
    plan_reconciliation,
    verify_and_report,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def needs_approval(state: GitOpsState) -> str:
    """Route based on whether the plan requires human approval.

    If approval is required or there are no drift items, skip to END.
    Otherwise, proceed to apply the changes.
    """
    if not state.drift_items:
        return END

    if state.plan is not None and state.plan.requires_approval:
        logger.info(
            "gitops_approval_required",
            request_id=state.request_id,
            risk=state.plan.estimated_risk,
        )
        return END

    return "apply_reconciliation"


def create_gitops_graph() -> StateGraph[GitOpsState]:
    """Build the GitOps Agent LangGraph workflow.

    Workflow:
        detect_drift → plan_reconciliation
            → [conditional: needs_approval? END : apply_reconciliation]
            → verify_and_report → END
    """
    graph = StateGraph(GitOpsState)

    _go = "gitops"
    graph.add_node(
        "detect_drift",
        traced_node("gitops.detect_drift", _go)(detect_drift),
    )
    graph.add_node(
        "plan_reconciliation",
        traced_node("gitops.plan_reconciliation", _go)(plan_reconciliation),
    )
    graph.add_node(
        "apply_reconciliation",
        traced_node("gitops.apply_reconciliation", _go)(apply_reconciliation),
    )
    graph.add_node(
        "verify_and_report",
        traced_node("gitops.verify_and_report", _go)(verify_and_report),
    )

    # Define edges
    graph.set_entry_point("detect_drift")
    graph.add_edge("detect_drift", "plan_reconciliation")
    graph.add_conditional_edges(
        "plan_reconciliation",
        needs_approval,
        {
            "apply_reconciliation": "apply_reconciliation",
            END: END,
        },
    )
    graph.add_edge("apply_reconciliation", "verify_and_report")
    graph.add_edge("verify_and_report", END)

    return graph

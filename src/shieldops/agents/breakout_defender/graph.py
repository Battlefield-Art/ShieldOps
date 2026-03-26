"""LangGraph workflow definition for the Breakout Defender Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.breakout_defender.models import (
    BreakoutDefenderState,
)
from shieldops.agents.breakout_defender.nodes import (
    analyze_lateral_movement,
    assess_breakout_risk,
    detect_initial_access,
    execute_containment,
    report,
    verify_containment,
)
from shieldops.agents.tracing import traced_node


def should_analyze_lateral(
    state: BreakoutDefenderState,
) -> str:
    """Route after initial access detection."""
    if state.error:
        return "report"
    if state.initial_access_detected:
        return "analyze_lateral_movement"
    return "report"


def should_contain(
    state: BreakoutDefenderState,
) -> str:
    """Route after risk assessment — contain or report."""
    if state.breakout_risk_score >= 50.0:
        return "execute_containment"
    return "report"


def create_breakout_defender_graph() -> StateGraph[BreakoutDefenderState]:
    """Build the Breakout Defender LangGraph workflow.

    Workflow:
        detect_initial_access
          -> [detected? -> analyze_lateral_movement
              -> assess_breakout_risk
              -> [risk>=50? -> execute_containment
                  -> verify_containment]]
          -> report
    """
    graph = StateGraph(BreakoutDefenderState)

    _agent = "breakout_defender"
    graph.add_node(
        "detect_initial_access",
        traced_node(
            "breakout_defender.detect_initial_access",
            _agent,
        )(detect_initial_access),
    )
    graph.add_node(
        "analyze_lateral_movement",
        traced_node(
            "breakout_defender.analyze_lateral",
            _agent,
        )(analyze_lateral_movement),
    )
    graph.add_node(
        "assess_breakout_risk",
        traced_node(
            "breakout_defender.assess_risk",
            _agent,
        )(assess_breakout_risk),
    )
    graph.add_node(
        "execute_containment",
        traced_node(
            "breakout_defender.execute_containment",
            _agent,
        )(execute_containment),
    )
    graph.add_node(
        "verify_containment",
        traced_node(
            "breakout_defender.verify_containment",
            _agent,
        )(verify_containment),
    )
    graph.add_node(
        "report",
        traced_node(
            "breakout_defender.report",
            _agent,
        )(report),
    )

    # Define edges
    graph.set_entry_point("detect_initial_access")
    graph.add_conditional_edges(
        "detect_initial_access",
        should_analyze_lateral,
        {
            "analyze_lateral_movement": ("analyze_lateral_movement"),
            "report": "report",
        },
    )
    graph.add_edge(
        "analyze_lateral_movement",
        "assess_breakout_risk",
    )
    graph.add_conditional_edges(
        "assess_breakout_risk",
        should_contain,
        {
            "execute_containment": ("execute_containment"),
            "report": "report",
        },
    )
    graph.add_edge(
        "execute_containment",
        "verify_containment",
    )
    graph.add_edge(
        "verify_containment",
        "report",
    )
    graph.add_edge("report", END)

    return graph

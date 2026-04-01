"""LangGraph workflow for the Risk Appetite Engine Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.risk_appetite_engine.models import (
    RiskAppetiteEngineState,
)
from shieldops.agents.risk_appetite_engine.nodes import (
    compare_thresholds,
    define_appetite,
    generate_report,
    identify_breaches,
    measure_exposure,
    recommend_adjustments,
)
from shieldops.agents.tracing import traced_node

_AGENT = "risk_appetite_engine"


def _should_identify(
    state: RiskAppetiteEngineState,
) -> str:
    """Route after threshold comparison."""
    if state.error:
        return "generate_report"
    if state.threshold_comparisons:
        return "identify_breaches"
    return "generate_report"


def _should_recommend(
    state: RiskAppetiteEngineState,
) -> str:
    """Route after breach identification."""
    if state.breach_records:
        return "recommend_adjustments"
    return "generate_report"


def create_risk_appetite_engine_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Risk Appetite Engine LangGraph.

    Workflow:
        define_appetite -> measure_exposure -> compare_thresholds
          -> [has_comparisons?] -> identify_breaches
          -> [has_breaches?] -> recommend_adjustments
          -> generate_report
    """
    graph = StateGraph(RiskAppetiteEngineState)

    graph.add_node(
        "define_appetite",
        traced_node(f"{_AGENT}.define_appetite", _AGENT)(
            define_appetite,
        ),
    )
    graph.add_node(
        "measure_exposure",
        traced_node(f"{_AGENT}.measure_exposure", _AGENT)(
            measure_exposure,
        ),
    )
    graph.add_node(
        "compare_thresholds",
        traced_node(f"{_AGENT}.compare_thresholds", _AGENT)(
            compare_thresholds,
        ),
    )
    graph.add_node(
        "identify_breaches",
        traced_node(f"{_AGENT}.identify_breaches", _AGENT)(
            identify_breaches,
        ),
    )
    graph.add_node(
        "recommend_adjustments",
        traced_node(f"{_AGENT}.recommend_adjustments", _AGENT)(
            recommend_adjustments,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("define_appetite")
    graph.add_edge("define_appetite", "measure_exposure")
    graph.add_edge("measure_exposure", "compare_thresholds")
    graph.add_conditional_edges(
        "compare_thresholds",
        _should_identify,
        {
            "identify_breaches": "identify_breaches",
            "generate_report": "generate_report",
        },
    )
    graph.add_conditional_edges(
        "identify_breaches",
        _should_recommend,
        {
            "recommend_adjustments": "recommend_adjustments",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("recommend_adjustments", "generate_report")
    graph.add_edge("generate_report", END)

    return graph

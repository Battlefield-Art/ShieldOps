"""Security Awareness Engine Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityAwarenessEngineState
from .nodes import (
    analyze_phishing,
    assess_baseline,
    evaluate_training,
    generate_plan,
    generate_report,
    identify_risks,
)
from .tools import SecurityAwarenessEngineToolkit


def build_graph(
    toolkit: SecurityAwarenessEngineToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security Awareness Engine graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_baseline(_to_dict(state), toolkit)

    async def _phishing(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_phishing(_to_dict(state), toolkit)

    async def _training(
        state: Any,
    ) -> dict[str, Any]:
        return await evaluate_training(_to_dict(state), toolkit)

    async def _risks(
        state: Any,
    ) -> dict[str, Any]:
        return await identify_risks(_to_dict(state), toolkit)

    async def _plan(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_plan(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(SecurityAwarenessEngineState)
    graph.add_node("assess_baseline", _assess)
    graph.add_node("analyze_phishing", _phishing)
    graph.add_node("evaluate_training", _training)
    graph.add_node("identify_risks", _risks)
    graph.add_node("generate_plan", _plan)
    graph.add_node("report", _report)

    graph.set_entry_point("assess_baseline")
    graph.add_edge("assess_baseline", "analyze_phishing")
    graph.add_edge("analyze_phishing", "evaluate_training")
    graph.add_edge("evaluate_training", "identify_risks")
    graph.add_edge("identify_risks", "generate_plan")
    graph.add_edge("generate_plan", "report")
    graph.add_edge("report", END)

    return graph


def create_security_awareness_engine_graph(
    lms_client: Any | None = None,
    phishing_client: Any | None = None,
    hr_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Factory: create the Security Awareness Engine graph."""
    toolkit = SecurityAwarenessEngineToolkit(
        lms_client=lms_client,
        phishing_client=phishing_client,
        hr_client=hr_client,
    )
    return build_graph(toolkit)

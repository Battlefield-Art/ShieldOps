"""WAF Manager — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import WAFManagerState
from .nodes import (
    analyze_attacks,
    auto_block,
    evaluate_coverage,
    ingest_logs,
    reduce_false_positives,
    report,
    tune_rules,
)
from .tools import WAFManagerToolkit


def _has_high_volume(state: Any) -> str:
    """Route based on attack volume."""
    if hasattr(state, "attack_summary"):
        summary = state.attack_summary
    else:
        summary = state.get("attack_summary", {})
    total = summary.get("total_events", 0) if summary else 0
    if total > 0:
        return "evaluate"
    return "report"


def build_graph(
    toolkit: WAFManagerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the WAF Manager graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _ingest(state: Any) -> dict[str, Any]:
        return await ingest_logs(_to_dict(state), toolkit)

    async def _analyze(state: Any) -> dict[str, Any]:
        return await analyze_attacks(_to_dict(state), toolkit)

    async def _coverage(state: Any) -> dict[str, Any]:
        return await evaluate_coverage(_to_dict(state), toolkit)

    async def _tune(state: Any) -> dict[str, Any]:
        return await tune_rules(_to_dict(state), toolkit)

    async def _fps(state: Any) -> dict[str, Any]:
        return await reduce_false_positives(
            _to_dict(state),
            toolkit,
        )

    async def _block(state: Any) -> dict[str, Any]:
        return await auto_block(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(WAFManagerState)
    graph.add_node("ingest_logs", _ingest)
    graph.add_node("analyze_attacks", _analyze)
    graph.add_node("evaluate_coverage", _coverage)
    graph.add_node("tune_rules", _tune)
    graph.add_node("reduce_false_positives", _fps)
    graph.add_node("auto_block", _block)
    graph.add_node("report", _report)

    graph.set_entry_point("ingest_logs")
    graph.add_edge("ingest_logs", "analyze_attacks")
    graph.add_conditional_edges(
        "analyze_attacks",
        _has_high_volume,
        {"evaluate": "evaluate_coverage", "report": "report"},
    )
    graph.add_edge("evaluate_coverage", "reduce_false_positives")
    graph.add_edge("reduce_false_positives", "tune_rules")
    graph.add_edge("tune_rules", "auto_block")
    graph.add_edge("auto_block", "report")
    graph.add_edge("report", END)

    return graph


def create_waf_manager_graph(
    waf_client: Any | None = None,
    log_store: Any | None = None,
    alert_sink: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the WAF Manager graph with dependencies."""
    toolkit = WAFManagerToolkit(
        waf_client=waf_client,
        log_store=log_store,
        alert_sink=alert_sink,
    )
    return build_graph(toolkit)

"""Alert Fatigue Reducer Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import AlertFatigueReducerState
from .nodes import (
    analyze_noise,
    collect_alerts,
    detect_fatigue,
    generate_report,
    tune_rules,
    validate_changes,
)
from .tools import AlertFatigueReducerToolkit


def build_graph(
    toolkit: AlertFatigueReducerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Alert Fatigue Reducer graph.

    Flow:
        collect_alerts -> analyze_noise
        -> detect_fatigue -> tune_rules
        -> validate -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_alerts(
            _to_dict(state),
            toolkit,
        )

    async def _noise(
        state: Any,
    ) -> dict[str, Any]:
        return await analyze_noise(
            _to_dict(state),
            toolkit,
        )

    async def _fatigue(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_fatigue(
            _to_dict(state),
            toolkit,
        )

    async def _tune(
        state: Any,
    ) -> dict[str, Any]:
        return await tune_rules(
            _to_dict(state),
            toolkit,
        )

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_changes(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(AlertFatigueReducerState)
    graph.add_node("collect_alerts", _collect)
    graph.add_node("analyze_noise", _noise)
    graph.add_node("detect_fatigue", _fatigue)
    graph.add_node("tune_rules", _tune)
    graph.add_node("validate", _validate)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_alerts")
    graph.add_edge(
        "collect_alerts",
        "analyze_noise",
    )
    graph.add_edge(
        "analyze_noise",
        "detect_fatigue",
    )
    graph.add_edge(
        "detect_fatigue",
        "tune_rules",
    )
    graph.add_edge(
        "tune_rules",
        "validate",
    )
    graph.add_edge(
        "validate",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_alert_fatigue_reducer_graph(
    siem_client: Any | None = None,
    soar_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Alert Fatigue Reducer graph."""
    toolkit = AlertFatigueReducerToolkit(
        siem_client=siem_client,
        soar_client=soar_client,
    )
    return build_graph(toolkit)

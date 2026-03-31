"""Security ROI Calculator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityROICalculatorState
from .nodes import (
    calculate_roi,
    collect_investments,
    compare_benchmarks,
    forecast_value,
    generate_report,
    measure_outcomes,
)
from .tools import SecurityROICalculatorToolkit


def build_graph(
    toolkit: SecurityROICalculatorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security ROI Calculator graph.

    Flow:
        collect_investments -> measure_outcomes
        -> calculate_roi -> compare_benchmarks
        -> forecast -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _collect(
        state: Any,
    ) -> dict[str, Any]:
        return await collect_investments(
            _to_dict(state),
            toolkit,
        )

    async def _measure(
        state: Any,
    ) -> dict[str, Any]:
        return await measure_outcomes(
            _to_dict(state),
            toolkit,
        )

    async def _calc_roi(
        state: Any,
    ) -> dict[str, Any]:
        return await calculate_roi(
            _to_dict(state),
            toolkit,
        )

    async def _benchmarks(
        state: Any,
    ) -> dict[str, Any]:
        return await compare_benchmarks(
            _to_dict(state),
            toolkit,
        )

    async def _forecast(
        state: Any,
    ) -> dict[str, Any]:
        return await forecast_value(
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

    graph = StateGraph(SecurityROICalculatorState)
    graph.add_node("collect_investments", _collect)
    graph.add_node("measure_outcomes", _measure)
    graph.add_node("calculate_roi", _calc_roi)
    graph.add_node("compare_benchmarks", _benchmarks)
    graph.add_node("forecast", _forecast)
    graph.add_node("report", _report)

    graph.set_entry_point("collect_investments")
    graph.add_edge(
        "collect_investments",
        "measure_outcomes",
    )
    graph.add_edge(
        "measure_outcomes",
        "calculate_roi",
    )
    graph.add_edge(
        "calculate_roi",
        "compare_benchmarks",
    )
    graph.add_edge(
        "compare_benchmarks",
        "forecast",
    )
    graph.add_edge(
        "forecast",
        "report",
    )
    graph.add_edge("report", END)

    return graph


def create_security_roi_calculator_graph(
    finance_api: Any | None = None,
    benchmark_db: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security ROI Calculator graph."""
    toolkit = SecurityROICalculatorToolkit(
        finance_api=finance_api,
        benchmark_db=benchmark_db,
    )
    return build_graph(toolkit)

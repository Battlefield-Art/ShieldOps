"""Security ROI Calculator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: SecurityROICalculatorToolkit):  # type: ignore[no-untyped-def]
    """Build the security_roi_calculator agent graph (linear sequence)."""
    return build_linear_graph(
        SecurityROICalculatorState,
        [
            ("collect_investments", collect_investments),
            ("measure_outcomes", measure_outcomes),
            ("calculate_roi", calculate_roi),
            ("compare_benchmarks", compare_benchmarks),
            ("forecast", forecast_value),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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

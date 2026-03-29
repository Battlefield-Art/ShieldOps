"""Incident Cost Calculator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.incident_cost_calculator.models import IncidentCostCalculatorState
from shieldops.agents.incident_cost_calculator.tools import IncidentCostCalculatorToolkit

logger = structlog.get_logger()

_toolkit: IncidentCostCalculatorToolkit | None = None


def set_toolkit(toolkit: IncidentCostCalculatorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentCostCalculatorToolkit:
    if _toolkit is None:
        return IncidentCostCalculatorToolkit()
    return _toolkit


async def gather_metrics(
    state: IncidentCostCalculatorState,
) -> dict[str, Any]:
    """Execute gather_metrics."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "gather_metrics",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"gather_metrics done in {dur:.0f}ms",
        ],
    }


async def compute_direct(
    state: IncidentCostCalculatorState,
) -> dict[str, Any]:
    """Execute compute_direct."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "compute_direct",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_direct done in {dur:.0f}ms",
        ],
    }


async def compute_indirect(
    state: IncidentCostCalculatorState,
) -> dict[str, Any]:
    """Execute compute_indirect."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "compute_indirect",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_indirect done in {dur:.0f}ms",
        ],
    }


async def project_long_term(
    state: IncidentCostCalculatorState,
) -> dict[str, Any]:
    """Execute project_long_term."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "project_long_term",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"project_long_term done in {dur:.0f}ms",
        ],
    }


async def benchmark(
    state: IncidentCostCalculatorState,
) -> dict[str, Any]:
    """Execute benchmark."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "benchmark",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"benchmark done in {dur:.0f}ms",
        ],
    }


async def report(
    state: IncidentCostCalculatorState,
) -> dict[str, Any]:
    """Execute report."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report done in {dur:.0f}ms",
        ],
    }

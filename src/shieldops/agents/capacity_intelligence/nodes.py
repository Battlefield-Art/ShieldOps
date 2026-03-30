"""Capacity Intelligence Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.capacity_intelligence.models import (
    CapacityIntelligenceState,
)
from shieldops.agents.capacity_intelligence.tools import (
    CapacityIntelligenceToolkit,
)

logger = structlog.get_logger()

_toolkit: CapacityIntelligenceToolkit | None = None


def set_toolkit(
    toolkit: CapacityIntelligenceToolkit,
) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CapacityIntelligenceToolkit:
    if _toolkit is None:
        return CapacityIntelligenceToolkit()
    return _toolkit


async def collect_utilization(
    state: CapacityIntelligenceState,
) -> dict[str, Any]:
    """Collect resource utilization."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.collect_utilization()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_utilization",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_utilization done in {dur:.0f}ms",
        ],
    }


async def forecast_demand(
    state: CapacityIntelligenceState,
) -> dict[str, Any]:
    """Forecast future demand."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.forecast_demand()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "forecast_demand",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"forecast_demand done in {dur:.0f}ms",
        ],
    }


async def identify_bottlenecks(
    state: CapacityIntelligenceState,
) -> dict[str, Any]:
    """Identify resource bottlenecks."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.identify_bottlenecks()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_bottlenecks",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_bottlenecks done in {dur:.0f}ms",
        ],
    }


async def optimize_resources(
    state: CapacityIntelligenceState,
) -> dict[str, Any]:
    """Optimize resource allocation."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.optimize_resources()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "optimize_resources",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"optimize_resources done in {dur:.0f}ms",
        ],
    }


async def plan_scaling(
    state: CapacityIntelligenceState,
) -> dict[str, Any]:
    """Plan scaling actions."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.plan_scaling()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "plan_scaling",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"plan_scaling done in {dur:.0f}ms",
        ],
    }


async def report(
    state: CapacityIntelligenceState,
) -> dict[str, Any]:
    """Generate final report."""
    return {
        "current_step": "report",
        "stats": {
            "total_findings": len(state.findings),
            "steps": len(state.reasoning_chain),
        },
        "reasoning_chain": [
            *state.reasoning_chain,
            "report generated",
        ],
    }

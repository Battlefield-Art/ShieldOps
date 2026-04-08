"""SOC Metrics Dashboard Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.soc_metrics_dashboard.models import SocMetricsDashboardState
from shieldops.agents.soc_metrics_dashboard.tools import SocMetricsDashboardToolkit

logger = structlog.get_logger()

_toolkit: SocMetricsDashboardToolkit | None = None


def _get_toolkit() -> SocMetricsDashboardToolkit:
    if _toolkit is None:
        return SocMetricsDashboardToolkit()
    return _toolkit


async def collect_data(
    state: SocMetricsDashboardState,
) -> dict[str, Any]:
    """Execute collect_data."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_data done in {dur:.0f}ms",
        ],
    }


async def compute_kpis(
    state: SocMetricsDashboardState,
) -> dict[str, Any]:
    """Execute compute_kpis."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "compute_kpis",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_kpis done in {dur:.0f}ms",
        ],
    }


async def identify_trends(
    state: SocMetricsDashboardState,
) -> dict[str, Any]:
    """Execute identify_trends."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_trends",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_trends done in {dur:.0f}ms",
        ],
    }


async def benchmark(
    state: SocMetricsDashboardState,
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


async def recommend(
    state: SocMetricsDashboardState,
) -> dict[str, Any]:
    """Execute recommend."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend done in {dur:.0f}ms",
        ],
    }


async def report(
    state: SocMetricsDashboardState,
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

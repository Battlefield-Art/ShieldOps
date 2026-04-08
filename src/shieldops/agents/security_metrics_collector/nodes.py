"""Security Metrics Collector Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.security_metrics_collector.models import SecurityMetricsCollectorState
from shieldops.agents.security_metrics_collector.tools import SecurityMetricsCollectorToolkit

logger = structlog.get_logger()

_toolkit: SecurityMetricsCollectorToolkit | None = None


def _get_toolkit() -> SecurityMetricsCollectorToolkit:
    if _toolkit is None:
        return SecurityMetricsCollectorToolkit()
    return _toolkit


async def define_metrics(
    state: SecurityMetricsCollectorState,
) -> dict[str, Any]:
    """Execute define_metrics."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "define_metrics",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"define_metrics done in {dur:.0f}ms",
        ],
    }


async def collect_data(
    state: SecurityMetricsCollectorState,
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


async def calculate_kpis(
    state: SecurityMetricsCollectorState,
) -> dict[str, Any]:
    """Execute calculate_kpis."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "calculate_kpis",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"calculate_kpis done in {dur:.0f}ms",
        ],
    }


async def benchmark_performance(
    state: SecurityMetricsCollectorState,
) -> dict[str, Any]:
    """Execute benchmark_performance."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "benchmark_performance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"benchmark_performance done in {dur:.0f}ms",
        ],
    }


async def generate_dashboard(
    state: SecurityMetricsCollectorState,
) -> dict[str, Any]:
    """Execute generate_dashboard."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_dashboard",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_dashboard done in {dur:.0f}ms",
        ],
    }


async def report(
    state: SecurityMetricsCollectorState,
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

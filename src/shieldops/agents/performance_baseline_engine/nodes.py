"""Performance Baseline Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.performance_baseline_engine.models import (
    PerformanceBaselineEngineState,
)
from shieldops.agents.performance_baseline_engine.tools import (
    PerformanceBaselineEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: PerformanceBaselineEngineToolkit | None = None


def _get_toolkit() -> PerformanceBaselineEngineToolkit:
    if _toolkit is None:
        return PerformanceBaselineEngineToolkit()
    return _toolkit


async def collect_metrics(
    state: PerformanceBaselineEngineState,
) -> dict[str, Any]:
    """Collect performance metrics."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.collect_metrics()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_metrics",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_metrics done in {dur:.0f}ms",
        ],
    }


async def establish_baselines(
    state: PerformanceBaselineEngineState,
) -> dict[str, Any]:
    """Establish performance baselines."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.establish_baselines()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "establish_baselines",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"establish_baselines done in {dur:.0f}ms",
        ],
    }


async def detect_regressions(
    state: PerformanceBaselineEngineState,
) -> dict[str, Any]:
    """Detect performance regressions."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.detect_regressions()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_regressions",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_regressions done in {dur:.0f}ms",
        ],
    }


async def analyze_trends(
    state: PerformanceBaselineEngineState,
) -> dict[str, Any]:
    """Analyze performance trends."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.analyze_trends()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_trends",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_trends done in {dur:.0f}ms",
        ],
    }


async def alert_deviations(
    state: PerformanceBaselineEngineState,
) -> dict[str, Any]:
    """Alert on baseline deviations."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.alert_deviations()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "alert_deviations",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"alert_deviations done in {dur:.0f}ms",
        ],
    }


async def report(
    state: PerformanceBaselineEngineState,
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

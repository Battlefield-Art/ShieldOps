"""Root Cause Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.root_cause_analyzer.models import (
    RootCauseAnalyzerState,
)
from shieldops.agents.root_cause_analyzer.tools import (
    RootCauseAnalyzerToolkit,
)

logger = structlog.get_logger()

_toolkit: RootCauseAnalyzerToolkit | None = None


def _get_toolkit() -> RootCauseAnalyzerToolkit:
    if _toolkit is None:
        return RootCauseAnalyzerToolkit()
    return _toolkit


async def collect_signals(
    state: RootCauseAnalyzerState,
) -> dict[str, Any]:
    """Collect signals from telemetry sources."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.collect_signals()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_signals",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_signals done in {dur:.0f}ms",
        ],
    }


async def build_graph(
    state: RootCauseAnalyzerState,
) -> dict[str, Any]:
    """Build causal dependency graph."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.build_graph()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "build_graph",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"build_graph done in {dur:.0f}ms",
        ],
    }


async def trace_causality(
    state: RootCauseAnalyzerState,
) -> dict[str, Any]:
    """Trace causal chains."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.trace_causality()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "trace_causality",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"trace_causality done in {dur:.0f}ms",
        ],
    }


async def rank_causes(
    state: RootCauseAnalyzerState,
) -> dict[str, Any]:
    """Rank candidate root causes."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.rank_causes()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "rank_causes",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"rank_causes done in {dur:.0f}ms",
        ],
    }


async def recommend_fixes(
    state: RootCauseAnalyzerState,
) -> dict[str, Any]:
    """Recommend fixes for root causes."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.recommend_fixes()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend_fixes",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend_fixes done in {dur:.0f}ms",
        ],
    }


async def report(
    state: RootCauseAnalyzerState,
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

"""Dependency Graph Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.dependency_graph_analyzer.models import DependencyGraphAnalyzerState
from shieldops.agents.dependency_graph_analyzer.tools import DependencyGraphAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: DependencyGraphAnalyzerToolkit | None = None


def _get_toolkit() -> DependencyGraphAnalyzerToolkit:
    if _toolkit is None:
        return DependencyGraphAnalyzerToolkit()
    return _toolkit


async def build_graph(
    state: DependencyGraphAnalyzerState,
) -> dict[str, Any]:
    """Execute build_graph."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "build_graph",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"build_graph done in {dur:.0f}ms",
        ],
    }


async def analyze_depth(
    state: DependencyGraphAnalyzerState,
) -> dict[str, Any]:
    """Execute analyze_depth."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_depth",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_depth done in {dur:.0f}ms",
        ],
    }


async def find_bottlenecks(
    state: DependencyGraphAnalyzerState,
) -> dict[str, Any]:
    """Execute find_bottlenecks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "find_bottlenecks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"find_bottlenecks done in {dur:.0f}ms",
        ],
    }


async def detect_cycles(
    state: DependencyGraphAnalyzerState,
) -> dict[str, Any]:
    """Execute detect_cycles."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_cycles",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_cycles done in {dur:.0f}ms",
        ],
    }


async def score(
    state: DependencyGraphAnalyzerState,
) -> dict[str, Any]:
    """Execute score."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score done in {dur:.0f}ms",
        ],
    }


async def report(
    state: DependencyGraphAnalyzerState,
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

"""Attack Path Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.attack_path_analyzer.models import AttackPathAnalyzerState
from shieldops.agents.attack_path_analyzer.tools import AttackPathAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: AttackPathAnalyzerToolkit | None = None


def _get_toolkit() -> AttackPathAnalyzerToolkit:
    if _toolkit is None:
        return AttackPathAnalyzerToolkit()
    return _toolkit


async def discover_assets(
    state: AttackPathAnalyzerState,
) -> dict[str, Any]:
    """Execute discover_assets."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_assets",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_assets done in {dur:.0f}ms",
        ],
    }


async def map_relationships(
    state: AttackPathAnalyzerState,
) -> dict[str, Any]:
    """Execute map_relationships."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_relationships",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_relationships done in {dur:.0f}ms",
        ],
    }


async def identify_paths(
    state: AttackPathAnalyzerState,
) -> dict[str, Any]:
    """Execute identify_paths."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_paths",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_paths done in {dur:.0f}ms",
        ],
    }


async def calculate_risk(
    state: AttackPathAnalyzerState,
) -> dict[str, Any]:
    """Execute calculate_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "calculate_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"calculate_risk done in {dur:.0f}ms",
        ],
    }


async def recommend_mitigations(
    state: AttackPathAnalyzerState,
) -> dict[str, Any]:
    """Execute recommend_mitigations."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "recommend_mitigations",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"recommend_mitigations done in {dur:.0f}ms",
        ],
    }


async def report(
    state: AttackPathAnalyzerState,
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

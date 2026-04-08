"""Kill Chain Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.kill_chain_analyzer.models import KillChainAnalyzerState
from shieldops.agents.kill_chain_analyzer.tools import KillChainAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: KillChainAnalyzerToolkit | None = None


def _get_toolkit() -> KillChainAnalyzerToolkit:
    if _toolkit is None:
        return KillChainAnalyzerToolkit()
    return _toolkit


async def ingest_alerts(
    state: KillChainAnalyzerState,
) -> dict[str, Any]:
    """Execute ingest_alerts."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "ingest_alerts",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"ingest_alerts done in {dur:.0f}ms",
        ],
    }


async def map_kill_chain(
    state: KillChainAnalyzerState,
) -> dict[str, Any]:
    """Execute map_kill_chain."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_kill_chain",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_kill_chain done in {dur:.0f}ms",
        ],
    }


async def identify_gaps(
    state: KillChainAnalyzerState,
) -> dict[str, Any]:
    """Execute identify_gaps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_gaps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_gaps done in {dur:.0f}ms",
        ],
    }


async def correlate_stages(
    state: KillChainAnalyzerState,
) -> dict[str, Any]:
    """Execute correlate_stages."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "correlate_stages",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"correlate_stages done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: KillChainAnalyzerState,
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
    state: KillChainAnalyzerState,
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

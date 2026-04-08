"""Threat Correlation Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_correlation_engine.models import ThreatCorrelationEngineState
from shieldops.agents.threat_correlation_engine.tools import ThreatCorrelationEngineToolkit

logger = structlog.get_logger()

_toolkit: ThreatCorrelationEngineToolkit | None = None


def _get_toolkit() -> ThreatCorrelationEngineToolkit:
    if _toolkit is None:
        return ThreatCorrelationEngineToolkit()
    return _toolkit


async def collect_events(
    state: ThreatCorrelationEngineState,
) -> dict[str, Any]:
    """Execute collect_events."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_events",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_events done in {dur:.0f}ms",
        ],
    }


async def normalize_data(
    state: ThreatCorrelationEngineState,
) -> dict[str, Any]:
    """Execute normalize_data."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "normalize_data",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"normalize_data done in {dur:.0f}ms",
        ],
    }


async def correlate_signals(
    state: ThreatCorrelationEngineState,
) -> dict[str, Any]:
    """Execute correlate_signals."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "correlate_signals",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"correlate_signals done in {dur:.0f}ms",
        ],
    }


async def score_threats(
    state: ThreatCorrelationEngineState,
) -> dict[str, Any]:
    """Execute score_threats."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score_threats",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score_threats done in {dur:.0f}ms",
        ],
    }


async def generate_alerts(
    state: ThreatCorrelationEngineState,
) -> dict[str, Any]:
    """Execute generate_alerts."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_alerts",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_alerts done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ThreatCorrelationEngineState,
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

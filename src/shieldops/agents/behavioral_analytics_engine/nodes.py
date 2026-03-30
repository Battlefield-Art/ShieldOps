"""Behavioral Analytics Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.behavioral_analytics_engine.models import (
    BehavioralAnalyticsEngineState,
)
from shieldops.agents.behavioral_analytics_engine.tools import (
    BehavioralAnalyticsEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: BehavioralAnalyticsEngineToolkit | None = None


def set_toolkit(
    toolkit: BehavioralAnalyticsEngineToolkit,
) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> BehavioralAnalyticsEngineToolkit:
    if _toolkit is None:
        return BehavioralAnalyticsEngineToolkit()
    return _toolkit


async def collect_telemetry(
    state: BehavioralAnalyticsEngineState,
) -> dict[str, Any]:
    """Collect behavioral telemetry."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.collect_telemetry()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_telemetry",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_telemetry done in {dur:.0f}ms",
        ],
    }


async def build_profiles(
    state: BehavioralAnalyticsEngineState,
) -> dict[str, Any]:
    """Build behavioral profiles."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.build_profiles()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "build_profiles",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"build_profiles done in {dur:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: BehavioralAnalyticsEngineState,
) -> dict[str, Any]:
    """Detect behavioral anomalies."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.detect_anomalies()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_anomalies",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_anomalies done in {dur:.0f}ms",
        ],
    }


async def score_risk(
    state: BehavioralAnalyticsEngineState,
) -> dict[str, Any]:
    """Score risk for detected anomalies."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.score_risk()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "score_risk",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"score_risk done in {dur:.0f}ms",
        ],
    }


async def alert_violations(
    state: BehavioralAnalyticsEngineState,
) -> dict[str, Any]:
    """Alert on behavioral violations."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.alert_violations()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "alert_violations",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"alert_violations done in {dur:.0f}ms",
        ],
    }


async def report(
    state: BehavioralAnalyticsEngineState,
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

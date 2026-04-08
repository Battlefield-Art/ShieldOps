"""Rate Limit Enforcer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.rate_limit_enforcer.models import (
    RateLimitEnforcerState,
)
from shieldops.agents.rate_limit_enforcer.tools import (
    RateLimitEnforcerToolkit,
)

logger = structlog.get_logger()

_toolkit: RateLimitEnforcerToolkit | None = None


def _get_toolkit() -> RateLimitEnforcerToolkit:
    if _toolkit is None:
        return RateLimitEnforcerToolkit()
    return _toolkit


async def monitor_traffic(
    state: RateLimitEnforcerState,
) -> dict[str, Any]:
    """Execute monitor_traffic."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.monitor_traffic()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "monitor_traffic",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"monitor_traffic done in {dur:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: RateLimitEnforcerState,
) -> dict[str, Any]:
    """Execute detect_anomalies."""
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


async def classify_patterns(
    state: RateLimitEnforcerState,
) -> dict[str, Any]:
    """Execute classify_patterns."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.classify_patterns()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_patterns",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_patterns done in {dur:.0f}ms",
        ],
    }


async def apply_limits(
    state: RateLimitEnforcerState,
) -> dict[str, Any]:
    """Execute apply_limits."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.apply_limits()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "apply_limits",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"apply_limits done in {dur:.0f}ms",
        ],
    }


async def notify_stakeholders(
    state: RateLimitEnforcerState,
) -> dict[str, Any]:
    """Execute notify_stakeholders."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.notify_stakeholders()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "notify_stakeholders",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"notify_stakeholders done in {dur:.0f}ms"),
        ],
    }


async def report(
    state: RateLimitEnforcerState,
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

"""Health Check Orchestrator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.health_check_orchestrator.models import (
    HealthCheckOrchestratorState,
)
from shieldops.agents.health_check_orchestrator.tools import (
    HealthCheckOrchestratorToolkit,
)

logger = structlog.get_logger()

_toolkit: HealthCheckOrchestratorToolkit | None = None


def set_toolkit(
    toolkit: HealthCheckOrchestratorToolkit,
) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> HealthCheckOrchestratorToolkit:
    if _toolkit is None:
        return HealthCheckOrchestratorToolkit()
    return _toolkit


async def discover_services(
    state: HealthCheckOrchestratorState,
) -> dict[str, Any]:
    """Execute discover_services."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.discover_services()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_services",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"discover_services done in {dur:.0f}ms"),
        ],
    }


async def probe_endpoints(
    state: HealthCheckOrchestratorState,
) -> dict[str, Any]:
    """Execute probe_endpoints."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.probe_endpoints()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "probe_endpoints",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"probe_endpoints done in {dur:.0f}ms",
        ],
    }


async def assess_health(
    state: HealthCheckOrchestratorState,
) -> dict[str, Any]:
    """Execute assess_health."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.assess_health()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_health",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_health done in {dur:.0f}ms",
        ],
    }


async def correlate_issues(
    state: HealthCheckOrchestratorState,
) -> dict[str, Any]:
    """Execute correlate_issues."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.correlate_issues()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "correlate_issues",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"correlate_issues done in {dur:.0f}ms"),
        ],
    }


async def trigger_remediation(
    state: HealthCheckOrchestratorState,
) -> dict[str, Any]:
    """Execute trigger_remediation."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.trigger_remediation()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "trigger_remediation",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"trigger_remediation done in {dur:.0f}ms"),
        ],
    }


async def report(
    state: HealthCheckOrchestratorState,
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

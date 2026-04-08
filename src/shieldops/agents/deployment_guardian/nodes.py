"""Deployment Guardian Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.deployment_guardian.models import (
    DeploymentGuardianState,
)
from shieldops.agents.deployment_guardian.tools import (
    DeploymentGuardianToolkit,
)

logger = structlog.get_logger()

_toolkit: DeploymentGuardianToolkit | None = None


def _get_toolkit() -> DeploymentGuardianToolkit:
    if _toolkit is None:
        return DeploymentGuardianToolkit()
    return _toolkit


async def analyze_changes(
    state: DeploymentGuardianState,
) -> dict[str, Any]:
    """Execute analyze_changes."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.analyze_changes()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_changes",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_changes done in {dur:.0f}ms",
        ],
    }


async def run_preflight(
    state: DeploymentGuardianState,
) -> dict[str, Any]:
    """Execute run_preflight."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.run_preflight()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "run_preflight",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"run_preflight done in {dur:.0f}ms",
        ],
    }


async def validate_security(
    state: DeploymentGuardianState,
) -> dict[str, Any]:
    """Execute validate_security."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.validate_security()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_security",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"validate_security done in {dur:.0f}ms"),
        ],
    }


async def approve_deployment(
    state: DeploymentGuardianState,
) -> dict[str, Any]:
    """Execute approve_deployment."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.approve_deployment()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "approve_deployment",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"approve_deployment done in {dur:.0f}ms"),
        ],
    }


async def monitor_rollout(
    state: DeploymentGuardianState,
) -> dict[str, Any]:
    """Execute monitor_rollout."""
    start = time.time()
    tk = _get_toolkit()
    results = await tk.monitor_rollout()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "monitor_rollout",
        "findings": [*state.findings, *results],
        "reasoning_chain": [
            *state.reasoning_chain,
            f"monitor_rollout done in {dur:.0f}ms",
        ],
    }


async def report(
    state: DeploymentGuardianState,
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

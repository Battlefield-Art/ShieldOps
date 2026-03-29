"""Permission Creep Analyzer Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.permission_creep_analyzer.models import PermissionCreepAnalyzerState
from shieldops.agents.permission_creep_analyzer.tools import PermissionCreepAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: PermissionCreepAnalyzerToolkit | None = None


def set_toolkit(toolkit: PermissionCreepAnalyzerToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PermissionCreepAnalyzerToolkit:
    if _toolkit is None:
        return PermissionCreepAnalyzerToolkit()
    return _toolkit


async def collect_permissions(
    state: PermissionCreepAnalyzerState,
) -> dict[str, Any]:
    """Execute collect_permissions."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_permissions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_permissions done in {dur:.0f}ms",
        ],
    }


async def baseline_role(
    state: PermissionCreepAnalyzerState,
) -> dict[str, Any]:
    """Execute baseline_role."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "baseline_role",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"baseline_role done in {dur:.0f}ms",
        ],
    }


async def detect_creep(
    state: PermissionCreepAnalyzerState,
) -> dict[str, Any]:
    """Execute detect_creep."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_creep",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_creep done in {dur:.0f}ms",
        ],
    }


async def assess_risk(
    state: PermissionCreepAnalyzerState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: PermissionCreepAnalyzerState,
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
    state: PermissionCreepAnalyzerState,
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

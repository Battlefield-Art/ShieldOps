"""Building Management Security Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.building_management_security.models import BuildingManagementSecurityState
from shieldops.agents.building_management_security.tools import BuildingManagementSecurityToolkit

logger = structlog.get_logger()

_toolkit: BuildingManagementSecurityToolkit | None = None


def set_toolkit(toolkit: BuildingManagementSecurityToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> BuildingManagementSecurityToolkit:
    if _toolkit is None:
        return BuildingManagementSecurityToolkit()
    return _toolkit


async def discover_systems(
    state: BuildingManagementSecurityState,
) -> dict[str, Any]:
    """Execute discover_systems."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "discover_systems",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_systems done in {duration:.0f}ms",
        ],
    }


async def audit_configs(
    state: BuildingManagementSecurityState,
) -> dict[str, Any]:
    """Execute audit_configs."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "audit_configs",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"audit_configs done in {duration:.0f}ms",
        ],
    }


async def check_access(
    state: BuildingManagementSecurityState,
) -> dict[str, Any]:
    """Execute check_access."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "check_access",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_access done in {duration:.0f}ms",
        ],
    }


async def detect_anomalies(
    state: BuildingManagementSecurityState,
) -> dict[str, Any]:
    """Execute detect_anomalies."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "detect_anomalies",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_anomalies done in {duration:.0f}ms",
        ],
    }


async def assess_risk(
    state: BuildingManagementSecurityState,
) -> dict[str, Any]:
    """Execute assess_risk."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "assess_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risk done in {duration:.0f}ms",
        ],
    }


async def report(
    state: BuildingManagementSecurityState,
) -> dict[str, Any]:
    """Execute report."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report done in {duration:.0f}ms",
        ],
    }

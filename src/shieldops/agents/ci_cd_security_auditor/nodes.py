"""CI/CD Security Auditor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.ci_cd_security_auditor.models import CiCdSecurityAuditorState
from shieldops.agents.ci_cd_security_auditor.tools import CiCdSecurityAuditorToolkit

logger = structlog.get_logger()

_toolkit: CiCdSecurityAuditorToolkit | None = None


def set_toolkit(toolkit: CiCdSecurityAuditorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CiCdSecurityAuditorToolkit:
    if _toolkit is None:
        return CiCdSecurityAuditorToolkit()
    return _toolkit


async def map_pipelines(
    state: CiCdSecurityAuditorState,
) -> dict[str, Any]:
    """Execute map_pipelines."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_pipelines",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_pipelines done in {dur:.0f}ms",
        ],
    }


async def check_permissions(
    state: CiCdSecurityAuditorState,
) -> dict[str, Any]:
    """Execute check_permissions."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_permissions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_permissions done in {dur:.0f}ms",
        ],
    }


async def scan_configs(
    state: CiCdSecurityAuditorState,
) -> dict[str, Any]:
    """Execute scan_configs."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "scan_configs",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"scan_configs done in {dur:.0f}ms",
        ],
    }


async def detect_injection(
    state: CiCdSecurityAuditorState,
) -> dict[str, Any]:
    """Execute detect_injection."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_injection",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"detect_injection done in {dur:.0f}ms",
        ],
    }


async def assess_risk(
    state: CiCdSecurityAuditorState,
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


async def report(
    state: CiCdSecurityAuditorState,
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

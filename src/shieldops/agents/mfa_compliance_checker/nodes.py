"""MFA Compliance Checker Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.mfa_compliance_checker.models import MfaComplianceCheckerState
from shieldops.agents.mfa_compliance_checker.tools import MfaComplianceCheckerToolkit

logger = structlog.get_logger()

_toolkit: MfaComplianceCheckerToolkit | None = None


def _get_toolkit() -> MfaComplianceCheckerToolkit:
    if _toolkit is None:
        return MfaComplianceCheckerToolkit()
    return _toolkit


async def discover_accounts(
    state: MfaComplianceCheckerState,
) -> dict[str, Any]:
    """Execute discover_accounts."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_accounts",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_accounts done in {dur:.0f}ms",
        ],
    }


async def check_mfa_status(
    state: MfaComplianceCheckerState,
) -> dict[str, Any]:
    """Execute check_mfa_status."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "check_mfa_status",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_mfa_status done in {dur:.0f}ms",
        ],
    }


async def classify_risk(
    state: MfaComplianceCheckerState,
) -> dict[str, Any]:
    """Execute classify_risk."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "classify_risk",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"classify_risk done in {dur:.0f}ms",
        ],
    }


async def enforce_policy(
    state: MfaComplianceCheckerState,
) -> dict[str, Any]:
    """Execute enforce_policy."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "enforce_policy",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"enforce_policy done in {dur:.0f}ms",
        ],
    }


async def report_gaps(
    state: MfaComplianceCheckerState,
) -> dict[str, Any]:
    """Execute report_gaps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "report_gaps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report_gaps done in {dur:.0f}ms",
        ],
    }


async def report(
    state: MfaComplianceCheckerState,
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

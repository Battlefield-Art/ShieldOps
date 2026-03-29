"""Compliance Automation Engine Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.compliance_automation_engine.models import (
    ComplianceAutomationEngineState,
)
from shieldops.agents.compliance_automation_engine.tools import (
    ComplianceAutomationEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: ComplianceAutomationEngineToolkit | None = None


def set_toolkit(toolkit: ComplianceAutomationEngineToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ComplianceAutomationEngineToolkit:
    if _toolkit is None:
        return ComplianceAutomationEngineToolkit()
    return _toolkit


async def discover_controls(
    state: ComplianceAutomationEngineState,
) -> dict[str, Any]:
    """Execute discover_controls."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "discover_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"discover_controls done in {dur:.0f}ms",
        ],
    }


async def test_controls(
    state: ComplianceAutomationEngineState,
) -> dict[str, Any]:
    """Execute test_controls."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "test_controls",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"test_controls done in {dur:.0f}ms",
        ],
    }


async def collect_evidence(
    state: ComplianceAutomationEngineState,
) -> dict[str, Any]:
    """Execute collect_evidence."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_evidence",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_evidence done in {dur:.0f}ms",
        ],
    }


async def assess_gaps(
    state: ComplianceAutomationEngineState,
) -> dict[str, Any]:
    """Execute assess_gaps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_gaps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_gaps done in {dur:.0f}ms",
        ],
    }


async def generate_attestation(
    state: ComplianceAutomationEngineState,
) -> dict[str, Any]:
    """Execute generate_attestation."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_attestation",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_attestation done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ComplianceAutomationEngineState,
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

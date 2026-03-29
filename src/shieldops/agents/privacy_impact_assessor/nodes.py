"""Privacy Impact Assessor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.privacy_impact_assessor.models import PrivacyImpactAssessorState
from shieldops.agents.privacy_impact_assessor.tools import PrivacyImpactAssessorToolkit

logger = structlog.get_logger()

_toolkit: PrivacyImpactAssessorToolkit | None = None


def set_toolkit(toolkit: PrivacyImpactAssessorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PrivacyImpactAssessorToolkit:
    if _toolkit is None:
        return PrivacyImpactAssessorToolkit()
    return _toolkit


async def identify_processing(
    state: PrivacyImpactAssessorState,
) -> dict[str, Any]:
    """Execute identify_processing."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_processing",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_processing done in {dur:.0f}ms",
        ],
    }


async def map_data_flows(
    state: PrivacyImpactAssessorState,
) -> dict[str, Any]:
    """Execute map_data_flows."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_data_flows",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_data_flows done in {dur:.0f}ms",
        ],
    }


async def assess_risks(
    state: PrivacyImpactAssessorState,
) -> dict[str, Any]:
    """Execute assess_risks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_risks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_risks done in {dur:.0f}ms",
        ],
    }


async def identify_mitigations(
    state: PrivacyImpactAssessorState,
) -> dict[str, Any]:
    """Execute identify_mitigations."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "identify_mitigations",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_mitigations done in {dur:.0f}ms",
        ],
    }


async def document(
    state: PrivacyImpactAssessorState,
) -> dict[str, Any]:
    """Execute document."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "document",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"document done in {dur:.0f}ms",
        ],
    }


async def report(
    state: PrivacyImpactAssessorState,
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

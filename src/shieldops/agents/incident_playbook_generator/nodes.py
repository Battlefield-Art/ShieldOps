"""Incident Playbook Generator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.incident_playbook_generator.models import (
    IncidentPlaybookGeneratorState,
)
from shieldops.agents.incident_playbook_generator.tools import (
    IncidentPlaybookGeneratorToolkit,
)

logger = structlog.get_logger()

_toolkit: IncidentPlaybookGeneratorToolkit | None = None


def set_toolkit(toolkit: IncidentPlaybookGeneratorToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentPlaybookGeneratorToolkit:
    if _toolkit is None:
        return IncidentPlaybookGeneratorToolkit()
    return _toolkit


async def analyze_threat(
    state: IncidentPlaybookGeneratorState,
) -> dict[str, Any]:
    """Execute analyze_threat."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_threat",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_threat done in {dur:.0f}ms",
        ],
    }


async def map_techniques(
    state: IncidentPlaybookGeneratorState,
) -> dict[str, Any]:
    """Execute map_techniques."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "map_techniques",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"map_techniques done in {dur:.0f}ms",
        ],
    }


async def design_workflow(
    state: IncidentPlaybookGeneratorState,
) -> dict[str, Any]:
    """Execute design_workflow."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "design_workflow",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"design_workflow done in {dur:.0f}ms",
        ],
    }


async def generate_steps(
    state: IncidentPlaybookGeneratorState,
) -> dict[str, Any]:
    """Execute generate_steps."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_steps",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_steps done in {dur:.0f}ms",
        ],
    }


async def validate_playbook(
    state: IncidentPlaybookGeneratorState,
) -> dict[str, Any]:
    """Execute validate_playbook."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "validate_playbook",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"validate_playbook done in {dur:.0f}ms",
        ],
    }


async def report(
    state: IncidentPlaybookGeneratorState,
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

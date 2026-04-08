"""Threat Brief Generator Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_brief_generator.models import ThreatBriefGeneratorState
from shieldops.agents.threat_brief_generator.tools import ThreatBriefGeneratorToolkit

logger = structlog.get_logger()

_toolkit: ThreatBriefGeneratorToolkit | None = None


def _get_toolkit() -> ThreatBriefGeneratorToolkit:
    if _toolkit is None:
        return ThreatBriefGeneratorToolkit()
    return _toolkit


async def collect_intel(
    state: ThreatBriefGeneratorState,
) -> dict[str, Any]:
    """Execute collect_intel."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "collect_intel",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_intel done in {dur:.0f}ms",
        ],
    }


async def analyze_threats(
    state: ThreatBriefGeneratorState,
) -> dict[str, Any]:
    """Execute analyze_threats."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_threats",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_threats done in {dur:.0f}ms",
        ],
    }


async def assess_relevance(
    state: ThreatBriefGeneratorState,
) -> dict[str, Any]:
    """Execute assess_relevance."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "assess_relevance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"assess_relevance done in {dur:.0f}ms",
        ],
    }


async def draft_brief(
    state: ThreatBriefGeneratorState,
) -> dict[str, Any]:
    """Execute draft_brief."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "draft_brief",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"draft_brief done in {dur:.0f}ms",
        ],
    }


async def review(
    state: ThreatBriefGeneratorState,
) -> dict[str, Any]:
    """Execute review."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "review",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"review done in {dur:.0f}ms",
        ],
    }


async def report(
    state: ThreatBriefGeneratorState,
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

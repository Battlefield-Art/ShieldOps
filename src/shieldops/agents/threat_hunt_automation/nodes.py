"""Node implementations for the Threat Hunt Automation Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_hunt_automation.tools import (
    ThreatHuntAutomationToolkit,
)

logger = structlog.get_logger()

_toolkit: ThreatHuntAutomationToolkit | None = None


def _get_toolkit() -> ThreatHuntAutomationToolkit:
    if _toolkit is None:
        return ThreatHuntAutomationToolkit()
    return _toolkit


async def generate_hypotheses(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate threat hunting hypotheses."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.generate_hypotheses(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "generate_hypotheses",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"generate_hypotheses done in {dur:.0f}ms",
        ],
    }


async def design_queries(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Design hunting queries for each hypothesis."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.design_queries(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "design_queries",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"design_queries done in {dur:.0f}ms",
        ],
    }


async def execute_hunts(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Execute hunting queries across telemetry."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.execute_hunts(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "execute_hunts",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"execute_hunts done in {dur:.0f}ms",
        ],
    }


async def analyze_results(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Analyze hunt execution results."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.analyze_results(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "analyze_results",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"analyze_results done in {dur:.0f}ms",
        ],
    }


async def document_findings(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Document hunt findings and evidence."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.document_findings(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "document_findings",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"document_findings done in {dur:.0f}ms",
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate threat hunt report."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.report(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "report",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"report done in {dur:.0f}ms",
        ],
    }

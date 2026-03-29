"""Node implementations for the Response Automation Engine."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.response_automation_engine.tools import (
    ResponseAutomationEngineToolkit,
)

logger = structlog.get_logger()

_toolkit: ResponseAutomationEngineToolkit | None = None


def set_toolkit(
    toolkit: ResponseAutomationEngineToolkit,
) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ResponseAutomationEngineToolkit:
    if _toolkit is None:
        return ResponseAutomationEngineToolkit()
    return _toolkit


async def detect_trigger(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Detect response triggers from alerts."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.detect_trigger(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "detect_trigger",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"detect_trigger done in {dur:.0f}ms",
        ],
    }


async def evaluate_playbook(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate and select response playbook."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.evaluate_playbook(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "evaluate_playbook",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"evaluate_playbook done in {dur:.0f}ms",
        ],
    }


async def orchestrate_actions(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Orchestrate automated response actions."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.orchestrate_actions(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "orchestrate_actions",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"orchestrate_actions done in {dur:.0f}ms",
        ],
    }


async def verify_response(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Verify response actions were effective."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.verify_response(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "verify_response",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"verify_response done in {dur:.0f}ms",
        ],
    }


async def document_actions(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Document all response actions taken."""
    start = time.time()
    toolkit = _get_toolkit()
    tid = state.get("tenant_id", "")
    results = await toolkit.document_actions(tid)
    chain = state.get("reasoning_chain", [])
    dur = (time.time() - start) * 1000
    return {
        "current_step": "document_actions",
        "findings": [
            *state.get("findings", []),
            *results,
        ],
        "reasoning_chain": [
            *chain,
            f"document_actions done in {dur:.0f}ms",
        ],
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate response automation report."""
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

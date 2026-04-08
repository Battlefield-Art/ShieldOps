"""Runbook Knowledge Base Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.runbook_knowledge_base.models import RunbookKnowledgeBaseState
from shieldops.agents.runbook_knowledge_base.tools import RunbookKnowledgeBaseToolkit

logger = structlog.get_logger()

_toolkit: RunbookKnowledgeBaseToolkit | None = None


def _get_toolkit() -> RunbookKnowledgeBaseToolkit:
    if _toolkit is None:
        return RunbookKnowledgeBaseToolkit()
    return _toolkit


async def index_runbooks(
    state: RunbookKnowledgeBaseState,
) -> dict[str, Any]:
    """Execute index_runbooks."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "index_runbooks",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"index_runbooks done in {dur:.0f}ms",
        ],
    }


async def extract_patterns(
    state: RunbookKnowledgeBaseState,
) -> dict[str, Any]:
    """Execute extract_patterns."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "extract_patterns",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"extract_patterns done in {dur:.0f}ms",
        ],
    }


async def build_search(
    state: RunbookKnowledgeBaseState,
) -> dict[str, Any]:
    """Execute build_search."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "build_search",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"build_search done in {dur:.0f}ms",
        ],
    }


async def recommend(
    state: RunbookKnowledgeBaseState,
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


async def feedback(
    state: RunbookKnowledgeBaseState,
) -> dict[str, Any]:
    """Execute feedback."""
    start = time.time()
    _get_toolkit()
    dur = (time.time() - start) * 1000
    return {
        "current_step": "feedback",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"feedback done in {dur:.0f}ms",
        ],
    }


async def report(
    state: RunbookKnowledgeBaseState,
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

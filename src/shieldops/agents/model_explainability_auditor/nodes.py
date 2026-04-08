"""Model Explainability Auditor Agent nodes."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.model_explainability_auditor.models import ModelExplainabilityAuditorState
from shieldops.agents.model_explainability_auditor.tools import ModelExplainabilityAuditorToolkit

logger = structlog.get_logger()

_toolkit: ModelExplainabilityAuditorToolkit | None = None


def _get_toolkit() -> ModelExplainabilityAuditorToolkit:
    if _toolkit is None:
        return ModelExplainabilityAuditorToolkit()
    return _toolkit


async def collect_predictions(
    state: ModelExplainabilityAuditorState,
) -> dict[str, Any]:
    """Execute collect_predictions."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "collect_predictions",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"collect_predictions done in {duration:.0f}ms",
        ],
    }


async def compute_importance(
    state: ModelExplainabilityAuditorState,
) -> dict[str, Any]:
    """Execute compute_importance."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "compute_importance",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"compute_importance done in {duration:.0f}ms",
        ],
    }


async def analyze_shap(
    state: ModelExplainabilityAuditorState,
) -> dict[str, Any]:
    """Execute analyze_shap."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "analyze_shap",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"analyze_shap done in {duration:.0f}ms",
        ],
    }


async def check_fairness(
    state: ModelExplainabilityAuditorState,
) -> dict[str, Any]:
    """Execute check_fairness."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "check_fairness",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"check_fairness done in {duration:.0f}ms",
        ],
    }


async def generate_report(
    state: ModelExplainabilityAuditorState,
) -> dict[str, Any]:
    """Execute generate_report."""
    start = time.time()
    _get_toolkit()
    duration = (time.time() - start) * 1000
    return {
        "current_step": "generate_report",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"generate_report done in {duration:.0f}ms",
        ],
    }


async def report(
    state: ModelExplainabilityAuditorState,
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

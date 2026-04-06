"""Secrets in Code Detector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import SecretsInCodeDetectorState
from .nodes import (
    assess_exposure,
    discover_repositories,
    generate_report,
    prioritize_findings,
    scan_patterns,
    verify_secrets,
)
from .tools import SecretsInCodeDetectorToolkit


def build_graph(toolkit: SecretsInCodeDetectorToolkit):  # type: ignore[no-untyped-def]
    """Build the secrets_in_code_detector agent graph (linear sequence)."""
    return build_linear_graph(
        SecretsInCodeDetectorState,
        [
            ("discover_repositories", discover_repositories),
            ("scan_patterns", scan_patterns),
            ("verify_secrets", verify_secrets),
            ("assess_exposure", assess_exposure),
            ("prioritize", prioritize_findings),
            ("generate_report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_secrets_in_code_detector_graph(
    git_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Secrets in Code Detector graph with deps."""
    toolkit = SecretsInCodeDetectorToolkit(
        git_client=git_client,
    )
    return build_graph(toolkit)

"""Cloud Migration Planner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import CloudMigrationPlannerState
from .nodes import (
    assess_readiness,
    discover_workloads,
    execute_migration,
    generate_report,
    plan_migration,
    validate_dependencies,
)
from .tools import CloudMigrationPlannerToolkit


def build_graph(toolkit: CloudMigrationPlannerToolkit):  # type: ignore[no-untyped-def]
    """Build the cloud_migration_planner agent graph (linear sequence)."""
    return build_linear_graph(
        CloudMigrationPlannerState,
        [
            ("discover_workloads", discover_workloads),
            ("assess_readiness", assess_readiness),
            ("plan_migration", plan_migration),
            ("validate_dependencies", validate_dependencies),
            ("execute_migration", execute_migration),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_cloud_migration_planner_graph(
    discovery_api: Any | None = None,
    cloud_provider: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Cloud Migration Planner graph."""
    toolkit = CloudMigrationPlannerToolkit(
        discovery_api=discovery_api,
        cloud_provider=cloud_provider,
    )
    return build_graph(toolkit)

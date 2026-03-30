"""Cloud Migration Planner Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: CloudMigrationPlannerToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Cloud Migration Planner graph.

    Flow:
        discover_workloads -> assess_readiness
        -> plan_migration -> validate_dependencies
        -> execute_migration -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _discover(
        state: Any,
    ) -> dict[str, Any]:
        return await discover_workloads(
            _to_dict(state),
            toolkit,
        )

    async def _assess(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_readiness(
            _to_dict(state),
            toolkit,
        )

    async def _plan(
        state: Any,
    ) -> dict[str, Any]:
        return await plan_migration(
            _to_dict(state),
            toolkit,
        )

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_dependencies(
            _to_dict(state),
            toolkit,
        )

    async def _execute(
        state: Any,
    ) -> dict[str, Any]:
        return await execute_migration(
            _to_dict(state),
            toolkit,
        )

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(CloudMigrationPlannerState)
    graph.add_node("discover_workloads", _discover)
    graph.add_node("assess_readiness", _assess)
    graph.add_node("plan_migration", _plan)
    graph.add_node(
        "validate_dependencies",
        _validate,
    )
    graph.add_node("execute_migration", _execute)
    graph.add_node("report", _report)

    graph.set_entry_point("discover_workloads")
    graph.add_edge(
        "discover_workloads",
        "assess_readiness",
    )
    graph.add_edge(
        "assess_readiness",
        "plan_migration",
    )
    graph.add_edge(
        "plan_migration",
        "validate_dependencies",
    )
    graph.add_edge(
        "validate_dependencies",
        "execute_migration",
    )
    graph.add_edge(
        "execute_migration",
        "report",
    )
    graph.add_edge("report", END)

    return graph


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

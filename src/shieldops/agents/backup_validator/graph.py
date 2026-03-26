"""Backup Validator Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import BackupValidatorState
from .nodes import (
    assess_gaps,
    generate_report,
    inventory_backups,
    remediate,
    test_recovery,
    validate_integrity,
)
from .tools import BackupValidatorToolkit


def build_graph(toolkit: BackupValidatorToolkit) -> StateGraph:  # type: ignore[type-arg]
    """Build the Backup Validator agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(state: Any) -> dict[str, Any]:
        return await inventory_backups(_to_dict(state), toolkit)

    async def _validate(state: Any) -> dict[str, Any]:
        return await validate_integrity(_to_dict(state), toolkit)

    async def _test(state: Any) -> dict[str, Any]:
        return await test_recovery(_to_dict(state), toolkit)

    async def _assess(state: Any) -> dict[str, Any]:
        return await assess_gaps(_to_dict(state), toolkit)

    async def _remediate(state: Any) -> dict[str, Any]:
        return await remediate(_to_dict(state), toolkit)

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(_to_dict(state), toolkit)

    graph = StateGraph(BackupValidatorState)
    graph.add_node("inventory_backups", _inventory)
    graph.add_node("validate_integrity", _validate)
    graph.add_node("test_recovery", _test)
    graph.add_node("assess_gaps", _assess)
    graph.add_node("remediate", _remediate)
    graph.add_node("report", _report)

    graph.set_entry_point("inventory_backups")
    graph.add_edge("inventory_backups", "validate_integrity")
    graph.add_edge("validate_integrity", "test_recovery")
    graph.add_edge("test_recovery", "assess_gaps")
    graph.add_edge("assess_gaps", "remediate")
    graph.add_edge("remediate", "report")
    graph.add_edge("report", END)

    return graph


def create_backup_validator_graph(
    backup_client: Any | None = None,
    storage_client: Any | None = None,
    recovery_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Backup Validator agent graph with dependencies."""
    toolkit = BackupValidatorToolkit(
        backup_client=backup_client,
        storage_client=storage_client,
        recovery_client=recovery_client,
    )
    return build_graph(toolkit)

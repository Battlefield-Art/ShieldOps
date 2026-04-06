"""Backup Validator Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

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


def build_graph(toolkit: BackupValidatorToolkit):  # type: ignore[no-untyped-def]
    """Build the backup_validator agent graph (linear sequence)."""
    return build_linear_graph(
        BackupValidatorState,
        [
            ("inventory_backups", inventory_backups),
            ("validate_integrity", validate_integrity),
            ("test_recovery", test_recovery),
            ("assess_gaps", assess_gaps),
            ("remediate", remediate),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


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

"""Backup Security Posture Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import BackupSecurityPostureState
from .nodes import (
    assess_security_config,
    detect_vulnerabilities,
    inventory_backup_infra,
    recommend_hardening,
    report,
    test_recovery,
)
from .tools import BackupSecurityPostureToolkit


def build_graph(toolkit: BackupSecurityPostureToolkit):  # type: ignore[no-untyped-def]
    """Build the backup_security_posture agent graph (linear sequence)."""
    return build_linear_graph(
        BackupSecurityPostureState,
        [
            ("inventory_backup_infra", inventory_backup_infra),
            ("assess_security_config", assess_security_config),
            ("detect_vulnerabilities", detect_vulnerabilities),
            ("test_recovery", test_recovery),
            ("recommend_hardening", recommend_hardening),
            ("report", report),
        ],
        toolkit=toolkit,
    )


def create_backup_security_posture_graph(
    backup_api: Any | None = None,
    vuln_scanner: Any | None = None,
    dr_tester: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Backup Security Posture graph."""
    toolkit = BackupSecurityPostureToolkit(
        backup_api=backup_api,
        vuln_scanner=vuln_scanner,
        dr_tester=dr_tester,
    )
    return build_graph(toolkit)

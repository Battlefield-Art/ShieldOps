"""Backup Security Posture Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

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


def build_graph(
    toolkit: BackupSecurityPostureToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Backup Security Posture graph.

    Flow:
        inventory_backup_infra
        -> assess_security_config
        -> detect_vulnerabilities
        -> test_recovery
        -> recommend_hardening -> report
    """

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _inventory(
        state: Any,
    ) -> dict[str, Any]:
        return await inventory_backup_infra(_to_dict(state), toolkit)

    async def _config(
        state: Any,
    ) -> dict[str, Any]:
        return await assess_security_config(_to_dict(state), toolkit)

    async def _vulns(
        state: Any,
    ) -> dict[str, Any]:
        return await detect_vulnerabilities(_to_dict(state), toolkit)

    async def _recovery(
        state: Any,
    ) -> dict[str, Any]:
        return await test_recovery(_to_dict(state), toolkit)

    async def _harden(
        state: Any,
    ) -> dict[str, Any]:
        return await recommend_hardening(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(BackupSecurityPostureState)
    graph.add_node("inventory_backup_infra", _inventory)
    graph.add_node("assess_security_config", _config)
    graph.add_node("detect_vulnerabilities", _vulns)
    graph.add_node("test_recovery", _recovery)
    graph.add_node("recommend_hardening", _harden)
    graph.add_node("report", _report)

    graph.set_entry_point("inventory_backup_infra")
    graph.add_edge(
        "inventory_backup_infra",
        "assess_security_config",
    )
    graph.add_edge(
        "assess_security_config",
        "detect_vulnerabilities",
    )
    graph.add_edge(
        "detect_vulnerabilities",
        "test_recovery",
    )
    graph.add_edge("test_recovery", "recommend_hardening")
    graph.add_edge("recommend_hardening", "report")
    graph.add_edge("report", END)

    return graph


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

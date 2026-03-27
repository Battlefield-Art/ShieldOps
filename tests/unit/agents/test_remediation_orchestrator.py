"""Tests for remediation_orchestrator."""

from __future__ import annotations

from shieldops.agents.remediation_orchestrator.models import (
    RemediationOrchestratorState,
)


class TestModels:
    def test_state_defaults(self):
        s = RemediationOrchestratorState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.remediation_orchestrator.graph import (
            create_remediation_orchestrator_graph,
        )

        assert create_remediation_orchestrator_graph().compile() is not None

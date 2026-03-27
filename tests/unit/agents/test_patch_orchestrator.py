"""Tests for patch_orchestrator."""

from __future__ import annotations

from shieldops.agents.patch_orchestrator.models import (
    PatchOrchestratorState,
)


class TestModels:
    def test_state_defaults(self):
        s = PatchOrchestratorState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.patch_orchestrator.graph import create_patch_orchestrator_graph

        assert create_patch_orchestrator_graph().compile() is not None

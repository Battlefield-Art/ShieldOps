"""Tests for shieldops.agents.automation_orchestrator."""

from __future__ import annotations

from shieldops.agents.automation_orchestrator.models import (
    AutomationState,
)


class TestModels:
    def test_state_exists(self):
        assert AutomationState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.automation_orchestrator.graph import (
            create_automation_graph,
        )

        sg = create_automation_graph()
        assert sg.compile() is not None

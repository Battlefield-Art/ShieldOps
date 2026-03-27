"""Tests for shieldops.agents.intelligent_automation."""

from __future__ import annotations

from shieldops.agents.intelligent_automation.models import (
    IntelligentAutomationState,
)


class TestModels:
    def test_state_defaults(self):
        s = IntelligentAutomationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.intelligent_automation.graph import (
            create_intelligent_automation_graph,
        )

        sg = create_intelligent_automation_graph()
        assert sg.compile() is not None

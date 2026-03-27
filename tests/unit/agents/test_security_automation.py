"""Tests for shieldops.agents.security_automation."""

from __future__ import annotations

from shieldops.agents.security_automation.models import (
    SecurityAutomationState,
)


class TestModels:
    def test_state_defaults(self):
        s = SecurityAutomationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.security_automation.graph import (
            create_security_automation_graph,
        )

        sg = create_security_automation_graph()
        assert sg.compile() is not None

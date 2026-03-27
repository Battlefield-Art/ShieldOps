"""Tests for shieldops.agents.threat_automation."""

from __future__ import annotations

from shieldops.agents.threat_automation.models import (
    ThreatAutomationState,
)


class TestModels:
    def test_state_defaults(self):
        s = ThreatAutomationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_automation.graph import (
            create_threat_automation_graph,
        )

        sg = create_threat_automation_graph()
        assert sg.compile() is not None

"""Tests for shieldops.agents.runbook_automation."""

from __future__ import annotations

from shieldops.agents.runbook_automation.models import (
    RunbookAutomationState,
)


class TestModels:
    def test_state_defaults(self):
        s = RunbookAutomationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.runbook_automation.graph import (
            create_runbook_automation_graph,
        )

        sg = create_runbook_automation_graph()
        assert sg.compile() is not None

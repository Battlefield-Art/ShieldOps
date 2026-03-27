"""Tests for shieldops.agents.auto_remediation."""

from __future__ import annotations

from shieldops.agents.auto_remediation.models import (
    AutoRemediationState,
)


class TestModels:
    def test_state_defaults(self):
        s = AutoRemediationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.auto_remediation.graph import (
            create_auto_remediation_graph,
        )

        sg = create_auto_remediation_graph()
        assert sg.compile() is not None

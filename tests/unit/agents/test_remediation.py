"""Tests for shieldops.agents.remediation."""

from __future__ import annotations

from shieldops.agents.remediation.models import (
    RemediationState,
)


class TestModels:
    def test_state_exists(self):
        assert RemediationState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.remediation.graph import (
            create_remediation_graph,
        )

        sg = create_remediation_graph()
        assert sg.compile() is not None

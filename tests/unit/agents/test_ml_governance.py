"""Tests for shieldops.agents.ml_governance."""

from __future__ import annotations

from shieldops.agents.ml_governance.models import (
    MLGovernanceState,
)


class TestModels:
    def test_state_defaults(self):
        s = MLGovernanceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ml_governance.graph import (
            create_ml_governance_graph,
        )

        sg = create_ml_governance_graph()
        assert sg.compile() is not None

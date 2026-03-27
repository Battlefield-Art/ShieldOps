"""Tests for shieldops.agents.cost."""

from __future__ import annotations

from shieldops.agents.cost.models import (
    CostAnalysisState,
)


class TestModels:
    def test_state_defaults(self):
        s = CostAnalysisState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cost.graph import (
            create_cost_graph,
        )

        sg = create_cost_graph()
        assert sg.compile() is not None

"""Tests for shieldops.agents.chaos_engineering."""

from __future__ import annotations

from shieldops.agents.chaos_engineering.models import (
    ChaosEngineeringState,
)


class TestModels:
    def test_state_defaults(self):
        s = ChaosEngineeringState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.chaos_engineering.graph import (
            create_chaos_engineering_graph,
        )

        sg = create_chaos_engineering_graph()
        assert sg.compile() is not None

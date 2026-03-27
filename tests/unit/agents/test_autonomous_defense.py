"""Tests for shieldops.agents.autonomous_defense."""

from __future__ import annotations

from shieldops.agents.autonomous_defense.models import (
    AutonomousDefenseState,
)


class TestModels:
    def test_state_defaults(self):
        s = AutonomousDefenseState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.autonomous_defense.graph import (
            create_autonomous_defense_graph,
        )

        sg = create_autonomous_defense_graph()
        assert sg.compile() is not None

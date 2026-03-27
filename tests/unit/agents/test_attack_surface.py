"""Tests for shieldops.agents.attack_surface."""

from __future__ import annotations

from shieldops.agents.attack_surface.models import (
    AttackSurfaceState,
)


class TestModels:
    def test_state_defaults(self):
        s = AttackSurfaceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.attack_surface.graph import (
            create_attack_surface_graph,
        )

        sg = create_attack_surface_graph()
        assert sg.compile() is not None

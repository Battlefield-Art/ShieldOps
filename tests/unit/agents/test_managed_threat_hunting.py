"""Tests for shieldops.agents.managed_threat_hunting."""

from __future__ import annotations

from shieldops.agents.managed_threat_hunting.models import (
    ManagedThreatHuntingState,
)


class TestModels:
    def test_state_defaults(self):
        s = ManagedThreatHuntingState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.managed_threat_hunting.graph import (
            create_managed_threat_hunting_graph,
        )

        sg = create_managed_threat_hunting_graph()
        assert sg.compile() is not None

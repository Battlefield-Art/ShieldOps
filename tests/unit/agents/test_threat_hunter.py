"""Tests for shieldops.agents.threat_hunter."""

from __future__ import annotations

from shieldops.agents.threat_hunter.models import (
    ThreatHunterState,
)


class TestModels:
    def test_state_defaults(self):
        s = ThreatHunterState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_hunter.graph import (
            create_threat_hunter_graph,
        )

        sg = create_threat_hunter_graph()
        assert sg.compile() is not None

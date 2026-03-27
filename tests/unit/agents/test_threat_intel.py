"""Tests for shieldops.agents.threat_intel."""

from __future__ import annotations

from shieldops.agents.threat_intel.models import (
    ThreatIntelState,
)


class TestModels:
    def test_state_defaults(self):
        s = ThreatIntelState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_intel.graph import (
            create_threat_intel_graph,
        )

        sg = create_threat_intel_graph()
        assert sg.compile() is not None

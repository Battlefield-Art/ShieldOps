"""Tests for shieldops.agents.threat_intelligence_platform."""

from __future__ import annotations

from shieldops.agents.threat_intelligence_platform.models import (
    ThreatIntelligencePlatformState,
)


class TestModels:
    def test_state_defaults(self):
        s = ThreatIntelligencePlatformState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_intelligence_platform.graph import (
            create_threat_intelligence_platform_graph,
        )

        sg = create_threat_intelligence_platform_graph()
        assert sg.compile() is not None

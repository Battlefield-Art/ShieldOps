"""Tests for shieldops.agents.platform_intelligence."""

from __future__ import annotations

from shieldops.agents.platform_intelligence.models import (
    PlatformIntelligenceState,
)


class TestModels:
    def test_state_defaults(self):
        s = PlatformIntelligenceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.platform_intelligence.graph import (
            create_platform_intelligence_graph,
        )

        sg = create_platform_intelligence_graph()
        assert sg.compile() is not None

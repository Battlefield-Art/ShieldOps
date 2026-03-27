"""Tests for shieldops.agents.observability_intelligence."""

from __future__ import annotations

from shieldops.agents.observability_intelligence.models import (
    ObservabilityIntelligenceState,
)


class TestModels:
    def test_state_defaults(self):
        s = ObservabilityIntelligenceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.observability_intelligence.graph import (
            create_observability_intelligence_graph,
        )

        sg = create_observability_intelligence_graph()
        assert sg.compile() is not None

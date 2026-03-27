"""Tests for shieldops.agents.log_intelligence."""

from __future__ import annotations

from shieldops.agents.log_intelligence.models import (
    LogIntelligenceState,
)


class TestModels:
    def test_state_defaults(self):
        s = LogIntelligenceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.log_intelligence.graph import (
            create_log_intelligence_graph,
        )

        sg = create_log_intelligence_graph()
        assert sg.compile() is not None

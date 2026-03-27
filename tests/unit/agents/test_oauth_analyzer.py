"""Tests for shieldops.agents.oauth_analyzer."""

from __future__ import annotations

from shieldops.agents.oauth_analyzer.models import (
    OAuthAnalyzerState,
)


class TestModels:
    def test_state_defaults(self):
        s = OAuthAnalyzerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.oauth_analyzer.graph import (
            create_oauth_analyzer_graph,
        )

        sg = create_oauth_analyzer_graph()
        assert sg.compile() is not None

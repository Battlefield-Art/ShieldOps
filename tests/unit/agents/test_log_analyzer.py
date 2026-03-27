"""Tests for shieldops.agents.log_analyzer."""

from __future__ import annotations

from shieldops.agents.log_analyzer.models import (
    LogAnalyzerState,
)


class TestModels:
    def test_state_defaults(self):
        s = LogAnalyzerState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.log_analyzer.graph import (
            create_log_analyzer_graph,
        )

        sg = create_log_analyzer_graph()
        assert sg.compile() is not None

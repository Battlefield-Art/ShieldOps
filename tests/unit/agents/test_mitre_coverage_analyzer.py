"""Tests for mitre_coverage_analyzer."""

from __future__ import annotations

from shieldops.agents.mitre_coverage_analyzer.models import (
    MITRECoverageAnalyzerState,
)


class TestModels:
    def test_state_defaults(self):
        s = MITRECoverageAnalyzerState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.mitre_coverage_analyzer.graph import (
            create_mitre_coverage_analyzer_graph,
        )

        assert create_mitre_coverage_analyzer_graph().compile() is not None

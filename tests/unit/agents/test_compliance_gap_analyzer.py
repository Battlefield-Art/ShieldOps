"""Tests for compliance_gap_analyzer."""

from __future__ import annotations

from shieldops.agents.compliance_gap_analyzer.models import (
    ComplianceGapAnalyzerState,
)


class TestModels:
    def test_state_defaults(self):
        s = ComplianceGapAnalyzerState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.compliance_gap_analyzer.graph import (
            create_compliance_gap_analyzer_graph,
        )

        assert create_compliance_gap_analyzer_graph().compile() is not None

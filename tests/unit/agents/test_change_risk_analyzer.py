"""Tests for shieldops.agents.change_risk_analyzer."""

from __future__ import annotations

from shieldops.agents.change_risk_analyzer.models import (
    AnalyzerStage,
    ChangeRiskAnalyzerState,
    ChangeType,
    RiskLevel,
)


class TestEnums:
    def test_analyzerstage_collect_change(self):
        assert AnalyzerStage.COLLECT_CHANGE == "collect_change"

    def test_analyzerstage_analyze_diff(self):
        assert AnalyzerStage.ANALYZE_DIFF == "analyze_diff"

    def test_analyzerstage_assess_risk(self):
        assert AnalyzerStage.ASSESS_RISK == "assess_risk"

    def test_analyzerstage_predict_blast_radius(self):
        assert AnalyzerStage.PREDICT_BLAST_RADIUS == "predict_blast_radius"

    def test_changetype_deployment(self):
        assert ChangeType.DEPLOYMENT == "deployment"

    def test_changetype_config_change(self):
        assert ChangeType.CONFIG_CHANGE == "config_change"

    def test_changetype_infrastructure(self):
        assert ChangeType.INFRASTRUCTURE == "infrastructure"

    def test_changetype_database_migration(self):
        assert ChangeType.DATABASE_MIGRATION == "database_migration"

    def test_risklevel_critical(self):
        assert RiskLevel.CRITICAL == "critical"

    def test_risklevel_high(self):
        assert RiskLevel.HIGH == "high"

    def test_risklevel_medium(self):
        assert RiskLevel.MEDIUM == "medium"

    def test_risklevel_low(self):
        assert RiskLevel.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = ChangeRiskAnalyzerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.change_risk_analyzer.graph import (
            create_change_risk_analyzer_graph,
        )

        sg = create_change_risk_analyzer_graph()
        assert sg.compile() is not None

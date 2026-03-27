"""Tests for shieldops.agents.risk_scoring."""

from __future__ import annotations

from shieldops.agents.risk_scoring.models import (
    MitreTactic,
    RiskLevel,
    RiskScoringState,
    RiskStage,
)


class TestEnums:
    def test_riskstage_collect(self):
        assert RiskStage.COLLECT == "collect"

    def test_riskstage_enrich(self):
        assert RiskStage.ENRICH == "enrich"

    def test_riskstage_aggregate(self):
        assert RiskStage.AGGREGATE == "aggregate"

    def test_riskstage_score(self):
        assert RiskStage.SCORE == "score"

    def test_mitretactic_initial_access(self):
        assert MitreTactic.INITIAL_ACCESS == "initial_access"

    def test_mitretactic_execution(self):
        assert MitreTactic.EXECUTION == "execution"

    def test_mitretactic_persistence(self):
        assert MitreTactic.PERSISTENCE == "persistence"

    def test_mitretactic_privilege_escalation(self):
        assert MitreTactic.PRIVILEGE_ESCALATION == "privilege_escalation"

    def test_risklevel_low(self):
        assert RiskLevel.LOW == "low"

    def test_risklevel_medium(self):
        assert RiskLevel.MEDIUM == "medium"

    def test_risklevel_high(self):
        assert RiskLevel.HIGH == "high"

    def test_risklevel_critical(self):
        assert RiskLevel.CRITICAL == "critical"


class TestModels:
    def test_state_exists(self):
        assert RiskScoringState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.risk_scoring.graph import build_graph
        from shieldops.agents.risk_scoring.tools import RiskScoringToolkit

        sg = build_graph(RiskScoringToolkit())
        assert sg.compile() is not None

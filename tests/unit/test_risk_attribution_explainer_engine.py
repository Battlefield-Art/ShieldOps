"""Tests for shieldops.security.risk_attribution_explainer_engine."""

from __future__ import annotations

from shieldops.security.risk_attribution_explainer_engine import (
    AttributionFactor,
    ExplanationDepth,
    ExplanationFormat,
    RiskAttributionAnalysis,
    RiskAttributionExplainerEngine,
    RiskAttributionRecord,
    RiskAttributionReport,
)


def _engine(**kw) -> RiskAttributionExplainerEngine:
    return RiskAttributionExplainerEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_depth_summary(self):
        assert ExplanationDepth.SUMMARY == "summary"

    def test_depth_detailed(self):
        assert ExplanationDepth.DETAILED == "detailed"

    def test_depth_technical(self):
        assert ExplanationDepth.TECHNICAL == "technical"

    def test_depth_executive(self):
        assert ExplanationDepth.EXECUTIVE == "executive"

    def test_factor_technique_weight(self):
        assert AttributionFactor.TECHNIQUE_WEIGHT == "technique_weight"

    def test_factor_entity_criticality(self):
        assert AttributionFactor.ENTITY_CRITICALITY == "entity_criticality"

    def test_format_narrative(self):
        assert ExplanationFormat.NARRATIVE == "narrative"

    def test_format_graph(self):
        assert ExplanationFormat.GRAPH == "graph"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = RiskAttributionRecord()
        assert r.id
        assert r.entity_id == ""
        assert r.risk_score == 0.0
        assert r.factor_contribution == 0.0

    def test_analysis_defaults(self):
        a = RiskAttributionAnalysis()
        assert a.triage_recommendation == ""
        assert a.dominant_factor == ""

    def test_report_defaults(self):
        r = RiskAttributionReport()
        assert r.total_records == 0
        assert r.top_attributed_entities == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            entity_id="user-001",
            risk_score=85.0,
            factor_contribution=40.0,
        )
        assert r.entity_id == "user-001"
        assert r.risk_score == 85.0

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(entity_id=f"e{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_escalate_high_risk(self):
        eng = _engine()
        r = eng.add_record(entity_id="e1", risk_score=95.0)
        result = eng.process(r.id)
        assert isinstance(result, RiskAttributionAnalysis)
        assert result.triage_recommendation == "escalate_immediately"

    def test_monitor_low_risk(self):
        eng = _engine()
        r = eng.add_record(entity_id="e2", risk_score=20.0)
        result = eng.process(r.id)
        assert result.triage_recommendation == "monitor"

    def test_investigate_mid_risk(self):
        eng = _engine()
        r = eng.add_record(entity_id="e3", risk_score=60.0)
        result = eng.process(r.id)
        assert result.triage_recommendation == "investigate"

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"


# --- generate_report ---


class TestGenerateReport:
    def test_high_risk_flagged(self):
        eng = _engine()
        eng.add_record(entity_id="e1", risk_score=90.0)
        eng.add_record(entity_id="e2", risk_score=20.0)
        report = eng.generate_report()
        assert "e1" in report.top_attributed_entities
        assert report.total_records == 2

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "adequate" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(attribution_factor=AttributionFactor.SOURCE_RELIABILITY)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "source_reliability" in stats["attribution_factor_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestGenerateRiskExplanation:
    def test_summary_depth(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            risk_score=70.0,
            attribution_factor=AttributionFactor.TECHNIQUE_WEIGHT,
            factor_contribution=50.0,
        )
        result = eng.generate_risk_explanation("e1", ExplanationDepth.SUMMARY)
        assert result["entity_id"] == "e1"
        assert result["avg_risk_score"] == 70.0
        assert "factor_breakdown" not in result

    def test_detailed_depth(self):
        eng = _engine()
        eng.add_record(
            entity_id="e2",
            risk_score=80.0,
            attribution_factor=AttributionFactor.ENTITY_CRITICALITY,
            factor_contribution=60.0,
        )
        result = eng.generate_risk_explanation("e2", ExplanationDepth.DETAILED)
        assert "factor_breakdown" in result

    def test_no_data(self):
        eng = _engine()
        result = eng.generate_risk_explanation("ghost")
        assert result["status"] == "no_data"


class TestIdentifyDominantFactors:
    def test_most_contributed(self):
        eng = _engine()
        eng.add_record(
            attribution_factor=AttributionFactor.TECHNIQUE_WEIGHT,
            factor_contribution=100.0,
        )
        eng.add_record(
            attribution_factor=AttributionFactor.SOURCE_RELIABILITY,
            factor_contribution=10.0,
        )
        results = eng.identify_dominant_factors()
        assert results[0]["factor"] == "technique_weight"

    def test_empty(self):
        eng = _engine()
        assert eng.identify_dominant_factors() == []


class TestGenerateTriageRecommendation:
    def test_critical(self):
        eng = _engine()
        eng.add_record(entity_id="e1", risk_score=92.0)
        result = eng.generate_triage_recommendation("e1")
        assert result["recommended_action"] == "escalate_immediately"
        assert result["severity"] == "critical"

    def test_monitor(self):
        eng = _engine()
        eng.add_record(entity_id="e2", risk_score=30.0)
        result = eng.generate_triage_recommendation("e2")
        assert result["recommended_action"] == "monitor"

    def test_no_data(self):
        eng = _engine()
        result = eng.generate_triage_recommendation("ghost")
        assert result["status"] == "no_data"

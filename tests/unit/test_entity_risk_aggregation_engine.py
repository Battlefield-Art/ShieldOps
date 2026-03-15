"""Tests for shieldops.security.entity_risk_aggregation_engine."""

from __future__ import annotations

from shieldops.security.entity_risk_aggregation_engine import (
    AggregationMethod,
    EntityRiskAggregationEngine,
    EntityRiskAnalysis,
    EntityRiskRecord,
    EntityRiskReport,
    EntityType,
    RiskTier,
)


def _engine(**kw) -> EntityRiskAggregationEngine:
    return EntityRiskAggregationEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_entity_type_user(self):
        assert EntityType.USER_ACCOUNT == "user_account"

    def test_entity_type_host(self):
        assert EntityType.HOST == "host"

    def test_entity_type_ip(self):
        assert EntityType.IP_ADDRESS == "ip_address"

    def test_entity_type_service_principal(self):
        assert EntityType.SERVICE_PRINCIPAL == "service_principal"

    def test_aggregation_weighted_sum(self):
        assert AggregationMethod.WEIGHTED_SUM == "weighted_sum"

    def test_aggregation_bayesian(self):
        assert AggregationMethod.BAYESIAN == "bayesian"

    def test_risk_tier_critical(self):
        assert RiskTier.CRITICAL == "critical"

    def test_risk_tier_low(self):
        assert RiskTier.LOW == "low"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = EntityRiskRecord()
        assert r.id
        assert r.entity_id == ""
        assert r.risk_score == 0.0
        assert r.contributor_scores == {}

    def test_analysis_defaults(self):
        a = EntityRiskAnalysis()
        assert a.composite_score == 0.0
        assert a.dominant_contributor == ""

    def test_report_defaults(self):
        r = EntityRiskReport()
        assert r.total_records == 0
        assert r.critical_entities == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            entity_id="user-001",
            entity_type=EntityType.USER_ACCOUNT,
            risk_score=75.0,
        )
        assert r.entity_id == "user-001"
        assert r.risk_score == 75.0

    def test_with_contributors(self):
        eng = _engine()
        r = eng.add_record(
            entity_id="host-001",
            contributor_scores={"malware": 30.0, "lateral": 20.0},
        )
        assert r.contributor_scores["malware"] == 30.0

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(4):
            eng.add_record(entity_id=f"e{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_found_with_contributors(self):
        eng = _engine()
        r = eng.add_record(
            entity_id="user-001",
            risk_score=80.0,
            contributor_scores={"malware": 50.0, "phishing": 30.0},
        )
        result = eng.process(r.id)
        assert isinstance(result, EntityRiskAnalysis)
        assert result.dominant_contributor == "malware"
        assert result.composite_score == 80.0

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"

    def test_no_contributors(self):
        eng = _engine()
        r = eng.add_record(entity_id="e1", risk_score=40.0)
        result = eng.process(r.id)
        assert isinstance(result, EntityRiskAnalysis)
        assert result.dominant_contributor == ""


# --- generate_report ---


class TestGenerateReport:
    def test_with_critical(self):
        eng = _engine()
        eng.add_record(entity_id="e1", risk_tier=RiskTier.CRITICAL)
        eng.add_record(entity_id="e2", risk_tier=RiskTier.LOW)
        report = eng.generate_report()
        assert "e1" in report.critical_entities
        assert "e2" not in report.critical_entities

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "acceptable" in report.recommendations[0]


# --- get_stats / clear_data ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(entity_type=EntityType.HOST)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "host" in stats["entity_type_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record(entity_id="e1")
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestCompositeRisk:
    def test_max_score(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            aggregation_method=AggregationMethod.MAX_SCORE,
            risk_score=90.0,
        )
        eng.add_record(
            entity_id="e1",
            aggregation_method=AggregationMethod.MAX_SCORE,
            risk_score=50.0,
        )
        results = eng.compute_composite_risk()
        assert results[0]["composite_score"] == 90.0

    def test_weighted_sum(self):
        eng = _engine()
        eng.add_record(
            entity_id="e2",
            aggregation_method=AggregationMethod.WEIGHTED_SUM,
            risk_score=60.0,
        )
        eng.add_record(
            entity_id="e2",
            aggregation_method=AggregationMethod.WEIGHTED_SUM,
            risk_score=40.0,
        )
        results = eng.compute_composite_risk()
        assert results[0]["composite_score"] == 50.0

    def test_empty(self):
        eng = _engine()
        assert eng.compute_composite_risk() == []


class TestDetectRiskConcentration:
    def test_concentrated(self):
        eng = _engine()
        for _ in range(5):
            eng.add_record(entity_id="dominant", risk_score=100.0)
        for _ in range(3):
            eng.add_record(entity_id="minor1", risk_score=1.0)
            eng.add_record(entity_id="minor2", risk_score=1.0)
            eng.add_record(entity_id="minor3", risk_score=1.0)
        results = eng.detect_risk_concentration(top_n=5)
        assert results[0]["entity_id"] == "dominant"
        assert results[0]["share_pct"] > 90.0

    def test_empty(self):
        eng = _engine()
        assert eng.detect_risk_concentration() == []


class TestDecomposeRiskContributors:
    def test_basic(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            contributor_scores={"malware": 40.0, "phish": 60.0},
        )
        result = eng.decompose_risk_contributors("e1")
        assert result["entity_id"] == "e1"
        assert result["contributors"][0]["contributor"] == "phish"

    def test_no_data(self):
        eng = _engine()
        result = eng.decompose_risk_contributors("ghost")
        assert result["status"] == "no_data"

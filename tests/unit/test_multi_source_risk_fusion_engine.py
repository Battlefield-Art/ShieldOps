"""Tests for shieldops.security.multi_source_risk_fusion_engine."""

from __future__ import annotations

from shieldops.security.multi_source_risk_fusion_engine import (
    FusionMethod,
    MultiSourceRiskAnalysis,
    MultiSourceRiskFusionEngine,
    MultiSourceRiskRecord,
    MultiSourceRiskReport,
    SourceAgreement,
    SourceCategory,
)


def _engine(**kw) -> MultiSourceRiskFusionEngine:
    return MultiSourceRiskFusionEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_source_siem(self):
        assert SourceCategory.SIEM == "siem"

    def test_source_edr(self):
        assert SourceCategory.EDR == "edr"

    def test_source_ndr(self):
        assert SourceCategory.NDR == "ndr"

    def test_source_casb(self):
        assert SourceCategory.CASB == "casb"

    def test_fusion_dempster(self):
        assert FusionMethod.DEMPSTER_SHAFER == "dempster_shafer"

    def test_fusion_voting(self):
        assert FusionMethod.VOTING == "voting"

    def test_agreement_consensus(self):
        assert SourceAgreement.CONSENSUS == "consensus"

    def test_agreement_contradictory(self):
        assert SourceAgreement.CONTRADICTORY == "contradictory"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = MultiSourceRiskRecord()
        assert r.id
        assert r.entity_id == ""
        assert r.source_weight == 1.0

    def test_analysis_defaults(self):
        a = MultiSourceRiskAnalysis()
        assert a.fused_risk_score == 0.0
        assert a.disagreement_detected is False

    def test_report_defaults(self):
        r = MultiSourceRiskReport()
        assert r.total_records == 0
        assert r.contradictory_entity_ids == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            entity_id="host-001",
            source_category=SourceCategory.SIEM,
            risk_score=70.0,
        )
        assert r.entity_id == "host-001"
        assert r.risk_score == 70.0

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(entity_id=f"e{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_weighted_average(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            risk_score=60.0,
            source_weight=1.0,
            fusion_method=FusionMethod.WEIGHTED_AVERAGE,
        )
        r = eng.add_record(
            entity_id="e1",
            risk_score=100.0,
            source_weight=1.0,
            fusion_method=FusionMethod.WEIGHTED_AVERAGE,
        )
        result = eng.process(r.id)
        assert isinstance(result, MultiSourceRiskAnalysis)
        assert result.fused_risk_score == 80.0

    def test_disagreement_detected(self):
        eng = _engine()
        eng.add_record(entity_id="e2", risk_score=10.0)
        r = eng.add_record(entity_id="e2", risk_score=90.0)
        result = eng.process(r.id)
        assert result.disagreement_detected is True

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"

    def test_voting_majority_high(self):
        eng = _engine()
        eng.add_record(
            entity_id="e3",
            risk_score=80.0,
            fusion_method=FusionMethod.VOTING,
        )
        r = eng.add_record(
            entity_id="e3",
            risk_score=70.0,
            fusion_method=FusionMethod.VOTING,
        )
        result = eng.process(r.id)
        assert result.fused_risk_score == 80.0


# --- generate_report ---


class TestGenerateReport:
    def test_contradictory_flagged(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            source_agreement=SourceAgreement.CONTRADICTORY,
        )
        report = eng.generate_report()
        assert "e1" in report.contradictory_entity_ids

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "agreement" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(source_category=SourceCategory.EDR)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "edr" in stats["source_category_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestFuseMultiSourceRisk:
    def test_hierarchical_max(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            risk_score=40.0,
            fusion_method=FusionMethod.HIERARCHICAL,
        )
        eng.add_record(
            entity_id="e1",
            risk_score=90.0,
            fusion_method=FusionMethod.HIERARCHICAL,
        )
        results = eng.fuse_multi_source_risk()
        assert results[0]["fused_risk_score"] == 90.0

    def test_empty(self):
        eng = _engine()
        assert eng.fuse_multi_source_risk() == []


class TestDetectSourceDisagreement:
    def test_disagreement(self):
        eng = _engine()
        eng.add_record(entity_id="e1", risk_score=10.0)
        eng.add_record(entity_id="e1", risk_score=80.0)
        results = eng.detect_source_disagreement(disagreement_threshold=40.0)
        assert len(results) == 1
        assert results[0]["entity_id"] == "e1"

    def test_no_disagreement(self):
        eng = _engine()
        eng.add_record(entity_id="e1", risk_score=50.0)
        eng.add_record(entity_id="e1", risk_score=55.0)
        results = eng.detect_source_disagreement(disagreement_threshold=40.0)
        assert results == []

    def test_single_source_skipped(self):
        eng = _engine()
        eng.add_record(entity_id="single", risk_score=90.0)
        results = eng.detect_source_disagreement()
        assert results == []


class TestEvaluateSourceContribution:
    def test_share_sums_to_100(self):
        eng = _engine()
        eng.add_record(source_category=SourceCategory.SIEM, risk_score=60.0)
        eng.add_record(source_category=SourceCategory.EDR, risk_score=40.0)
        results = eng.evaluate_source_contribution()
        total_share = sum(r["share_pct"] for r in results)
        assert abs(total_share - 100.0) < 0.01

    def test_empty(self):
        eng = _engine()
        assert eng.evaluate_source_contribution() == []

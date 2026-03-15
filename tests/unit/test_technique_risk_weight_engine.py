"""Tests for shieldops.security.technique_risk_weight_engine."""

from __future__ import annotations

import time

from shieldops.security.technique_risk_weight_engine import (
    TechniqueCategory,
    TechniquePrevalence,
    TechniqueRiskWeightAnalysis,
    TechniqueRiskWeightEngine,
    TechniqueRiskWeightRecord,
    TechniqueRiskWeightReport,
    WeightCalibration,
)


def _engine(**kw) -> TechniqueRiskWeightEngine:
    return TechniqueRiskWeightEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_category_initial_access(self):
        assert TechniqueCategory.INITIAL_ACCESS == "initial_access"

    def test_category_lateral_movement(self):
        assert TechniqueCategory.LATERAL_MOVEMENT == "lateral_movement"

    def test_category_exfiltration(self):
        assert TechniqueCategory.EXFILTRATION == "exfiltration"

    def test_category_persistence(self):
        assert TechniqueCategory.PERSISTENCE == "persistence"

    def test_calibration_static(self):
        assert WeightCalibration.STATIC == "static"

    def test_calibration_ml(self):
        assert WeightCalibration.ML_CALIBRATED == "ml_calibrated"

    def test_prevalence_common(self):
        assert TechniquePrevalence.COMMON == "common"

    def test_prevalence_novel(self):
        assert TechniquePrevalence.NOVEL == "novel"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = TechniqueRiskWeightRecord()
        assert r.id
        assert r.technique_id == ""
        assert r.risk_weight == 0.0
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = TechniqueRiskWeightAnalysis()
        assert a.id
        assert a.is_stale is False
        assert a.deviation_from_industry == 0.0

    def test_report_defaults(self):
        r = TechniqueRiskWeightReport()
        assert r.total_records == 0
        assert r.by_category == {}
        assert r.recommendations == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            technique_id="T1078",
            category=TechniqueCategory.INITIAL_ACCESS,
            risk_weight=75.0,
        )
        assert r.technique_id == "T1078"
        assert r.risk_weight == 75.0
        assert len(eng._records) == 1

    def test_eviction(self):
        eng = _engine(max_records=3)
        for i in range(5):
            eng.add_record(technique_id=f"T{i}")
        assert len(eng._records) == 3

    def test_default_calibration(self):
        eng = _engine()
        r = eng.add_record()
        assert r.calibration == WeightCalibration.STATIC


# --- process ---


class TestProcess:
    def test_found(self):
        eng = _engine()
        r = eng.add_record(technique_id="T1078", risk_weight=50.0, industry_baseline=40.0)
        result = eng.process(r.id)
        assert isinstance(result, TechniqueRiskWeightAnalysis)
        assert result.technique_id == "T1078"
        assert result.deviation_from_industry == 10.0

    def test_not_found(self):
        eng = _engine()
        result = eng.process("nonexistent")
        assert result == {"status": "not_found", "key": "nonexistent"}

    def test_stale_detection(self):
        eng = _engine()
        r = eng.add_record(
            technique_id="T1000",
            last_calibrated_at=time.time() - (86400 * 31),
        )
        result = eng.process(r.id)
        assert isinstance(result, TechniqueRiskWeightAnalysis)
        assert result.is_stale is True

    def test_not_stale(self):
        eng = _engine()
        r = eng.add_record(technique_id="T1001", last_calibrated_at=time.time())
        result = eng.process(r.id)
        assert isinstance(result, TechniqueRiskWeightAnalysis)
        assert result.is_stale is False


# --- generate_report ---


class TestGenerateReport:
    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "current" in report.recommendations[0]

    def test_with_data(self):
        eng = _engine()
        eng.add_record(technique_id="T1078", category=TechniqueCategory.EXFILTRATION)
        eng.add_record(technique_id="T1003", category=TechniqueCategory.PERSISTENCE)
        report = eng.generate_report()
        assert report.total_records == 2
        assert report.by_category != {}


# --- get_stats ---


class TestGetStats:
    def test_empty(self):
        eng = _engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["category_distribution"] == {}

    def test_populated(self):
        eng = _engine()
        eng.add_record(category=TechniqueCategory.INITIAL_ACCESS)
        stats = eng.get_stats()
        assert stats["total_records"] == 1


# --- clear_data ---


class TestClearData:
    def test_clears(self):
        eng = _engine()
        eng.add_record(technique_id="T1078")
        eng.clear_data()
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


# --- domain methods ---


class TestCalibrateWeights:
    def test_novel_amplified(self):
        eng = _engine()
        eng.add_record(
            technique_id="T1000",
            prevalence=TechniquePrevalence.NOVEL,
            risk_weight=100.0,
        )
        results = eng.calibrate_technique_weights()
        assert results[0]["calibrated_weight"] == 150.0

    def test_rare_reduced(self):
        eng = _engine()
        eng.add_record(
            technique_id="T1001",
            prevalence=TechniquePrevalence.RARE,
            risk_weight=100.0,
        )
        results = eng.calibrate_technique_weights()
        assert results[0]["calibrated_weight"] == 75.0

    def test_empty(self):
        eng = _engine()
        assert eng.calibrate_technique_weights() == []


class TestDetectWeightStaleness:
    def test_stale(self):
        eng = _engine()
        eng.add_record(
            technique_id="T1000",
            last_calibrated_at=time.time() - (86400 * 45),
        )
        results = eng.detect_weight_staleness(staleness_days=30)
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1000"

    def test_fresh(self):
        eng = _engine()
        eng.add_record(technique_id="T1000", last_calibrated_at=time.time())
        results = eng.detect_weight_staleness(staleness_days=30)
        assert results == []


class TestCompareWeightsToIndustry:
    def test_overweighted(self):
        eng = _engine()
        eng.add_record(
            technique_id="T1078",
            risk_weight=80.0,
            industry_baseline=60.0,
        )
        results = eng.compare_weights_to_industry()
        assert results[0]["delta"] == 20.0
        assert results[0]["overweighted"] is True

    def test_underweighted(self):
        eng = _engine()
        eng.add_record(
            technique_id="T1078",
            risk_weight=40.0,
            industry_baseline=60.0,
        )
        results = eng.compare_weights_to_industry()
        assert results[0]["delta"] == -20.0
        assert results[0]["overweighted"] is False

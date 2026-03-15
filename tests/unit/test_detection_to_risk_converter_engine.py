"""Tests for shieldops.security.detection_to_risk_converter_engine."""

from __future__ import annotations

from shieldops.security.detection_to_risk_converter_engine import (
    ConversionQuality,
    DetectionRiskAnalysis,
    DetectionRiskRecord,
    DetectionRiskReport,
    DetectionSource,
    DetectionToRiskConverterEngine,
    RiskContributionType,
)


def _engine(**kw) -> DetectionToRiskConverterEngine:
    return DetectionToRiskConverterEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_source_siem(self):
        assert DetectionSource.SIEM_RULE == "siem_rule"

    def test_source_ml(self):
        assert DetectionSource.ML_MODEL == "ml_model"

    def test_source_sigma(self):
        assert DetectionSource.SIGMA_RULE == "sigma_rule"

    def test_source_custom(self):
        assert DetectionSource.CUSTOM_DETECTION == "custom_detection"

    def test_quality_high_fidelity(self):
        assert ConversionQuality.HIGH_FIDELITY == "high_fidelity"

    def test_quality_unreliable(self):
        assert ConversionQuality.UNRELIABLE == "unreliable"

    def test_contribution_additive(self):
        assert RiskContributionType.ADDITIVE == "additive"

    def test_contribution_override(self):
        assert RiskContributionType.OVERRIDE == "override"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = DetectionRiskRecord()
        assert r.id
        assert r.detection_id == ""
        assert r.converted_risk_score == 0.0

    def test_analysis_defaults(self):
        a = DetectionRiskAnalysis()
        assert a.converted_risk == 0.0
        assert a.bias_detected is False

    def test_report_defaults(self):
        r = DetectionRiskReport()
        assert r.total_records == 0
        assert r.unreliable_sources == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            detection_id="D-001",
            source=DetectionSource.SIEM_RULE,
            converted_risk_score=70.0,
        )
        assert r.detection_id == "D-001"
        assert r.converted_risk_score == 70.0

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(detection_id=f"D-{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_bias_detected(self):
        eng = _engine()
        r = eng.add_record(detection_score=10.0, converted_risk_score=60.0)
        result = eng.process(r.id)
        assert isinstance(result, DetectionRiskAnalysis)
        assert result.bias_detected is True

    def test_no_bias(self):
        eng = _engine()
        r = eng.add_record(detection_score=50.0, converted_risk_score=55.0)
        result = eng.process(r.id)
        assert result.bias_detected is False

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"

    def test_quality_rating(self):
        eng = _engine()
        r = eng.add_record(
            conversion_quality=ConversionQuality.UNRELIABLE,
            detection_score=10.0,
            converted_risk_score=10.0,
        )
        result = eng.process(r.id)
        assert result.quality_rating == "unreliable"


# --- generate_report ---


class TestGenerateReport:
    def test_unreliable_flagged(self):
        eng = _engine()
        eng.add_record(
            source=DetectionSource.ML_MODEL,
            conversion_quality=ConversionQuality.UNRELIABLE,
        )
        report = eng.generate_report()
        assert "ml_model" in report.unreliable_sources

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "meeting" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(source=DetectionSource.SIGMA_RULE)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "sigma_rule" in stats["source_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


# --- domain methods ---


class TestConvertDetectionToRisk:
    def test_additive(self):
        eng = _engine()
        eng.add_record(
            entity_id="e1",
            contribution_type=RiskContributionType.ADDITIVE,
            converted_risk_score=30.0,
        )
        eng.add_record(
            entity_id="e1",
            contribution_type=RiskContributionType.ADDITIVE,
            converted_risk_score=20.0,
        )
        results = eng.convert_detection_to_risk()
        assert results[0]["aggregated_risk"] == 50.0

    def test_override(self):
        eng = _engine()
        eng.add_record(
            entity_id="e2",
            contribution_type=RiskContributionType.ADDITIVE,
            converted_risk_score=50.0,
        )
        eng.add_record(
            entity_id="e2",
            contribution_type=RiskContributionType.OVERRIDE,
            converted_risk_score=99.0,
        )
        results = eng.convert_detection_to_risk()
        assert results[0]["aggregated_risk"] == 99.0

    def test_empty(self):
        eng = _engine()
        assert eng.convert_detection_to_risk() == []


class TestEvaluateSourceReliability:
    def test_reliable(self):
        eng = _engine()
        eng.add_record(
            source=DetectionSource.SIEM_RULE,
            source_reliability=0.9,
            conversion_quality=ConversionQuality.HIGH_FIDELITY,
        )
        results = eng.evaluate_source_reliability()
        assert results[0]["source"] == "siem_rule"
        assert results[0]["needs_tuning"] is False

    def test_unreliable(self):
        eng = _engine()
        eng.add_record(
            source=DetectionSource.ML_MODEL,
            source_reliability=0.3,
            conversion_quality=ConversionQuality.UNRELIABLE,
        )
        results = eng.evaluate_source_reliability()
        assert results[0]["needs_tuning"] is True


class TestDetectConversionBias:
    def test_biased(self):
        eng = _engine()
        eng.add_record(
            source=DetectionSource.SIEM_RULE,
            detection_score=10.0,
            converted_risk_score=80.0,
        )
        results = eng.detect_conversion_bias(bias_threshold=30.0)
        assert results[0]["bias_detected"] is True
        assert results[0]["over_inflated"] is True

    def test_unbiased(self):
        eng = _engine()
        eng.add_record(
            source=DetectionSource.SIGMA_RULE,
            detection_score=50.0,
            converted_risk_score=55.0,
        )
        results = eng.detect_conversion_bias(bias_threshold=30.0)
        assert results[0]["bias_detected"] is False

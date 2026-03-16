"""Tests for shieldops.security.risk_factor_decay_engine."""

from __future__ import annotations

from shieldops.security.risk_factor_decay_engine import (
    DecayCurve,
    DecayHealth,
    DecayTrigger,
    RiskDecayAnalysis,
    RiskDecayRecord,
    RiskDecayReport,
    RiskFactorDecayEngine,
)


def _engine(**kw) -> RiskFactorDecayEngine:
    return RiskFactorDecayEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_curve_linear(self):
        assert DecayCurve.LINEAR == "linear"

    def test_curve_exponential(self):
        assert DecayCurve.EXPONENTIAL == "exponential"

    def test_curve_step(self):
        assert DecayCurve.STEP_FUNCTION == "step_function"

    def test_curve_sigmoid(self):
        assert DecayCurve.SIGMOID == "sigmoid"

    def test_trigger_time(self):
        assert DecayTrigger.TIME_ELAPSED == "time_elapsed"

    def test_health_active(self):
        assert DecayHealth.ACTIVE == "active"

    def test_health_expired(self):
        assert DecayHealth.EXPIRED == "expired"

    def test_health_near_zero(self):
        assert DecayHealth.NEAR_ZERO == "near_zero"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = RiskDecayRecord()
        assert r.id
        assert r.initial_risk == 0.0
        assert r.decay_rate == 0.0

    def test_analysis_defaults(self):
        a = RiskDecayAnalysis()
        assert a.anomaly_detected is False
        assert a.projected_risk == 0.0

    def test_report_defaults(self):
        r = RiskDecayReport()
        assert r.total_records == 0
        assert r.expired_factor_ids == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            factor_id="F-001",
            initial_risk=100.0,
            current_risk=60.0,
            decay_rate=0.1,
        )
        assert r.factor_id == "F-001"
        assert r.initial_risk == 100.0

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(factor_id=f"F-{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_anomaly_detected(self):
        eng = _engine()
        r = eng.add_record(initial_risk=50.0, current_risk=80.0)
        result = eng.process(r.id)
        assert isinstance(result, RiskDecayAnalysis)
        assert result.anomaly_detected is True

    def test_no_anomaly(self):
        eng = _engine()
        r = eng.add_record(initial_risk=100.0, current_risk=60.0)
        result = eng.process(r.id)
        assert result.anomaly_detected is False

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"

    def test_linear_time_to_zero(self):
        eng = _engine()
        r = eng.add_record(
            decay_curve=DecayCurve.LINEAR,
            current_risk=100.0,
            decay_rate=10.0,
        )
        result = eng.process(r.id)
        assert result.time_to_zero_hours == 10.0


# --- generate_report ---


class TestGenerateReport:
    def test_expired_flagged(self):
        eng = _engine()
        eng.add_record(factor_id="F-001", decay_health=DecayHealth.EXPIRED)
        report = eng.generate_report()
        assert "F-001" in report.expired_factor_ids
        assert "expired" in report.recommendations[0]

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "normal" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(decay_curve=DecayCurve.EXPONENTIAL)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "exponential" in stats["decay_curve_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestApplyDecayCurves:
    def test_linear(self):
        result = RiskFactorDecayEngine._apply_curve(DecayCurve.LINEAR, 100.0, 5.0, 10.0)
        assert result == 50.0

    def test_linear_floor_zero(self):
        result = RiskFactorDecayEngine._apply_curve(DecayCurve.LINEAR, 10.0, 100.0, 1.0)
        assert result == 0.0

    def test_exponential(self):
        result = RiskFactorDecayEngine._apply_curve(DecayCurve.EXPONENTIAL, 100.0, 0.0, 24.0)
        assert result == 100.0

    def test_step_function(self):
        result = RiskFactorDecayEngine._apply_curve(DecayCurve.STEP_FUNCTION, 100.0, 10.0, 48.0)
        assert result == 80.0


class TestApplyDecaySchedule:
    def test_projection(self):
        eng = _engine()
        eng.add_record(
            factor_id="F-001",
            current_risk=100.0,
            decay_curve=DecayCurve.LINEAR,
            decay_rate=5.0,
        )
        results = eng.apply_decay_schedule(projection_hours=10.0)
        assert results[0]["factor_id"] == "F-001"
        assert results[0]["projected_risk"] == 50.0

    def test_empty(self):
        eng = _engine()
        assert eng.apply_decay_schedule() == []


class TestDetectDecayAnomalies:
    def test_anti_decay_detected(self):
        eng = _engine()
        eng.add_record(factor_id="F-001", initial_risk=50.0, current_risk=80.0)
        results = eng.detect_decay_anomalies()
        assert len(results) == 1
        assert results[0]["growth_pct"] == 60.0

    def test_normal_decay(self):
        eng = _engine()
        eng.add_record(factor_id="F-001", initial_risk=100.0, current_risk=60.0)
        results = eng.detect_decay_anomalies()
        assert results == []


class TestOptimizeDecayParameters:
    def test_with_data(self):
        eng = _engine()
        eng.add_record(
            decay_curve=DecayCurve.LINEAR,
            initial_risk=100.0,
            current_risk=60.0,
            age_hours=8.0,
            decay_rate=5.0,
        )
        results = eng.optimize_decay_parameters()
        assert len(results) == 1
        assert results[0]["decay_curve"] == "linear"
        assert results[0]["recommended_decay_rate"] >= 0.0

    def test_empty(self):
        eng = _engine()
        assert eng.optimize_decay_parameters() == []

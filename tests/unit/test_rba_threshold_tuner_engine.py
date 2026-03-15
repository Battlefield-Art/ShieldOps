"""Tests for shieldops.security.rba_threshold_tuner_engine."""

from __future__ import annotations

from shieldops.security.rba_threshold_tuner_engine import (
    RbaThresholdTunerEngine,
    ThresholdDirection,
    ThresholdTunerAnalysis,
    ThresholdTunerRecord,
    ThresholdTunerReport,
    TuningOutcome,
    TuningStrategy,
)


def _engine(**kw) -> RbaThresholdTunerEngine:
    return RbaThresholdTunerEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_strategy_volume(self):
        assert TuningStrategy.VOLUME_BASED == "volume_based"

    def test_strategy_fpr(self):
        assert TuningStrategy.FPR_BASED == "fpr_based"

    def test_strategy_capacity(self):
        assert TuningStrategy.CAPACITY_BASED == "capacity_based"

    def test_strategy_hybrid(self):
        assert TuningStrategy.HYBRID == "hybrid"

    def test_direction_raise(self):
        assert ThresholdDirection.RAISE_THRESHOLD == "raise_threshold"

    def test_direction_lower(self):
        assert ThresholdDirection.LOWER_THRESHOLD == "lower_threshold"

    def test_outcome_reduced_noise(self):
        assert TuningOutcome.REDUCED_NOISE == "reduced_noise"

    def test_outcome_degraded(self):
        assert TuningOutcome.DEGRADED == "degraded"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = ThresholdTunerRecord()
        assert r.id
        assert r.rule_id == ""
        assert r.false_positive_rate == 0.0
        assert r.alert_volume == 0

    def test_analysis_defaults(self):
        a = ThresholdTunerAnalysis()
        assert a.effectiveness_score == 0.0
        assert a.adjustment_recommended is False

    def test_report_defaults(self):
        r = ThresholdTunerReport()
        assert r.total_records == 0
        assert r.high_fpr_rule_ids == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            rule_id="R-001",
            false_positive_rate=0.4,
            alert_volume=100,
        )
        assert r.rule_id == "R-001"
        assert r.false_positive_rate == 0.4

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(rule_id=f"R-{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_high_fpr_flags_adjustment(self):
        eng = _engine()
        r = eng.add_record(rule_id="R-001", false_positive_rate=0.5)
        result = eng.process(r.id)
        assert isinstance(result, ThresholdTunerAnalysis)
        assert result.adjustment_recommended is True

    def test_low_fpr_no_adjustment(self):
        eng = _engine()
        r = eng.add_record(rule_id="R-002", false_positive_rate=0.1)
        result = eng.process(r.id)
        assert result.adjustment_recommended is False

    def test_degraded_outcome_flags_adjustment(self):
        eng = _engine()
        r = eng.add_record(rule_id="R-003", tuning_outcome=TuningOutcome.DEGRADED)
        result = eng.process(r.id)
        assert result.adjustment_recommended is True

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"

    def test_effectiveness_score(self):
        eng = _engine()
        r = eng.add_record(rule_id="R-004", false_positive_rate=0.0)
        result = eng.process(r.id)
        assert result.effectiveness_score == 100.0


# --- generate_report ---


class TestGenerateReport:
    def test_high_fpr_flagged(self):
        eng = _engine()
        eng.add_record(rule_id="R-001", false_positive_rate=0.5)
        report = eng.generate_report()
        assert "R-001" in report.high_fpr_rule_ids

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "acceptable" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(tuning_strategy=TuningStrategy.HYBRID)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "hybrid" in stats["tuning_strategy_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestEvaluateThresholdEffectiveness:
    def test_needs_tuning(self):
        eng = _engine()
        eng.add_record(rule_id="R-001", false_positive_rate=0.5)
        results = eng.evaluate_threshold_effectiveness()
        assert results[0]["needs_tuning"] is True

    def test_good_rule(self):
        eng = _engine()
        eng.add_record(rule_id="R-002", false_positive_rate=0.05)
        results = eng.evaluate_threshold_effectiveness()
        assert results[0]["needs_tuning"] is False

    def test_empty(self):
        eng = _engine()
        assert eng.evaluate_threshold_effectiveness() == []


class TestRecommendThresholdAdjustments:
    def test_raise_for_high_fpr(self):
        eng = _engine()
        eng.add_record(
            rule_id="R-001",
            current_threshold=100.0,
            false_positive_rate=0.5,
            alert_volume=500,
        )
        results = eng.recommend_threshold_adjustments()
        assert results[0]["recommended_direction"] == "raise_threshold"

    def test_lower_for_low_volume(self):
        eng = _engine()
        eng.add_record(
            rule_id="R-002",
            current_threshold=100.0,
            false_positive_rate=0.02,
            alert_volume=5,
        )
        results = eng.recommend_threshold_adjustments()
        assert results[0]["recommended_direction"] == "lower_threshold"

    def test_empty(self):
        eng = _engine()
        assert eng.recommend_threshold_adjustments() == []


class TestSimulateThresholdChange:
    def test_suppression(self):
        eng = _engine()
        eng.add_record(rule_id="R-001", current_threshold=50.0)
        eng.add_record(rule_id="R-001", current_threshold=80.0)
        result = eng.simulate_threshold_change("R-001", 70.0)
        assert result["rule_id"] == "R-001"
        assert result["alerts_suppressed"] == 1

    def test_no_data(self):
        eng = _engine()
        result = eng.simulate_threshold_change("ghost", 50.0)
        assert result["status"] == "no_data"

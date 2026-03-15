"""Tests for shieldops.security.risk_notable_generator_engine."""

from __future__ import annotations

from shieldops.security.risk_notable_generator_engine import (
    NotableDisposition,
    NotablePriority,
    NotableTrigger,
    RiskNotableAnalysis,
    RiskNotableGeneratorEngine,
    RiskNotableRecord,
    RiskNotableReport,
)


def _engine(**kw) -> RiskNotableGeneratorEngine:
    return RiskNotableGeneratorEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_trigger_threshold(self):
        assert NotableTrigger.THRESHOLD_EXCEEDED == "threshold_exceeded"

    def test_trigger_spike(self):
        assert NotableTrigger.SPIKE_DETECTED == "spike_detected"

    def test_trigger_pattern(self):
        assert NotableTrigger.PATTERN_MATCH == "pattern_match"

    def test_trigger_anomaly(self):
        assert NotableTrigger.ANOMALY_CORRELATION == "anomaly_correlation"

    def test_priority_p1(self):
        assert NotablePriority.P1_IMMEDIATE == "p1_immediate"

    def test_priority_p4(self):
        assert NotablePriority.P4_LOW == "p4_low"

    def test_disposition_true_positive(self):
        assert NotableDisposition.TRUE_POSITIVE == "true_positive"

    def test_disposition_suppressed(self):
        assert NotableDisposition.SUPPRESSED == "suppressed"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = RiskNotableRecord()
        assert r.id
        assert r.notable_id == ""
        assert r.risk_score == 0.0
        assert r.fidelity_score == 0.0

    def test_analysis_defaults(self):
        a = RiskNotableAnalysis()
        assert a.fidelity_rating == ""
        assert a.urgency_rank == 0

    def test_report_defaults(self):
        r = RiskNotableReport()
        assert r.total_records == 0
        assert r.top_urgent_notables == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            notable_id="NB-001",
            priority=NotablePriority.P1_IMMEDIATE,
            risk_score=90.0,
        )
        assert r.notable_id == "NB-001"
        assert r.priority == NotablePriority.P1_IMMEDIATE

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(4):
            eng.add_record(notable_id=f"NB-{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_high_fidelity(self):
        eng = _engine()
        r = eng.add_record(notable_id="NB-001", fidelity_score=0.9, risk_score=50.0)
        result = eng.process(r.id)
        assert isinstance(result, RiskNotableAnalysis)
        assert result.fidelity_rating == "high"

    def test_low_fidelity(self):
        eng = _engine()
        r = eng.add_record(notable_id="NB-002", fidelity_score=0.3)
        result = eng.process(r.id)
        assert result.fidelity_rating == "low"

    def test_threshold_drift(self):
        eng = _engine()
        r = eng.add_record(
            notable_id="NB-003",
            risk_score=200.0,
            threshold_value=100.0,
        )
        result = eng.process(r.id)
        assert result.threshold_drift_detected is True

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"

    def test_urgency_p1(self):
        eng = _engine()
        r = eng.add_record(priority=NotablePriority.P1_IMMEDIATE)
        result = eng.process(r.id)
        assert result.urgency_rank == 4


# --- generate_report ---


class TestGenerateReport:
    def test_with_p1(self):
        eng = _engine()
        eng.add_record(notable_id="NB-001", priority=NotablePriority.P1_IMMEDIATE)
        report = eng.generate_report()
        assert "NB-001" in report.top_urgent_notables
        assert "P1" in report.recommendations[0]

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert report.total_records == 0


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats(self):
        eng = _engine()
        eng.add_record(trigger=NotableTrigger.SPIKE_DETECTED)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "spike_detected" in stats["trigger_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record(notable_id="NB-001")
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestEvaluateNotableFidelity:
    def test_with_true_positives(self):
        eng = _engine()
        eng.add_record(
            notable_id="NB-001",
            disposition=NotableDisposition.TRUE_POSITIVE,
            fidelity_score=0.9,
        )
        eng.add_record(
            notable_id="NB-001",
            disposition=NotableDisposition.BENIGN,
            fidelity_score=0.2,
        )
        results = eng.evaluate_notable_fidelity()
        assert results[0]["notable_id"] == "NB-001"
        assert results[0]["true_positive_count"] == 1

    def test_empty(self):
        eng = _engine()
        assert eng.evaluate_notable_fidelity() == []


class TestDetectThresholdDrift:
    def test_drift_detected(self):
        eng = _engine()
        eng.add_record(notable_id="NB-001", risk_score=200.0, threshold_value=100.0)
        results = eng.detect_threshold_drift(drift_multiplier=1.5)
        assert len(results) == 1
        assert results[0]["drift_ratio"] == 2.0

    def test_no_drift(self):
        eng = _engine()
        eng.add_record(notable_id="NB-001", risk_score=50.0, threshold_value=100.0)
        results = eng.detect_threshold_drift()
        assert results == []


class TestRankNotablesByUrgency:
    def test_p1_ranked_first(self):
        eng = _engine()
        eng.add_record(
            notable_id="NB-001",
            priority=NotablePriority.P1_IMMEDIATE,
            risk_score=80.0,
        )
        eng.add_record(
            notable_id="NB-002",
            priority=NotablePriority.P4_LOW,
            risk_score=80.0,
        )
        results = eng.rank_notables_by_urgency()
        assert results[0]["notable_id"] == "NB-001"
        assert results[0]["rank"] == 1

    def test_empty(self):
        eng = _engine()
        assert eng.rank_notables_by_urgency() == []

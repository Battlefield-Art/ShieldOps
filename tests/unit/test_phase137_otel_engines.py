"""Tests for Phase 137 OTel engines (semantic validation, log correlation, cross signal)."""

from __future__ import annotations

import pytest

from shieldops.observability.otel_semantic_validation_engine import (
    ComplianceLevel,
    FixComplexity,
    OtelSemanticValidationAnalysis,
    OtelSemanticValidationEngine,
    OtelSemanticValidationRecord,
    OtelSemanticValidationReport,
    SemanticScope,
)
from shieldops.observability.otel_log_correlation_engine import (
    CorrelationQuality,
    CorrelationStatus,
    LogLevel,
    OtelLogCorrelationAnalysis,
    OtelLogCorrelationEngine,
    OtelLogCorrelationRecord,
    OtelLogCorrelationReport,
)
from shieldops.observability.cross_signal_correlation_engine import (
    CorrelationStrength,
    CrossSignalCorrelationAnalysis,
    CrossSignalCorrelationEngine,
    CrossSignalCorrelationRecord,
    CrossSignalCorrelationReport,
    RootCauseConfidence,
    SignalType,
)


# ========== OtelSemanticValidationEngine ==========


class TestSemanticValidationEnums:
    def test_semantic_scope_values(self):
        assert SemanticScope.RESOURCE == "resource"
        assert SemanticScope.SPAN == "span"
        assert SemanticScope.METRIC == "metric"
        assert SemanticScope.LOG == "log"

    def test_compliance_level_values(self):
        assert ComplianceLevel.FULL == "full"
        assert ComplianceLevel.PARTIAL == "partial"
        assert ComplianceLevel.NONE == "none"

    def test_fix_complexity_values(self):
        assert FixComplexity.TRIVIAL == "trivial"
        assert FixComplexity.MODERATE == "moderate"
        assert FixComplexity.COMPLEX == "complex"


class TestSemanticValidationModels:
    def test_record_defaults(self):
        r = OtelSemanticValidationRecord()
        assert r.id
        assert r.name == ""
        assert r.semantic_scope == SemanticScope.RESOURCE
        assert r.compliance_level == ComplianceLevel.FULL
        assert r.fix_complexity == FixComplexity.TRIVIAL
        assert r.score == 0.0

    def test_analysis_defaults(self):
        a = OtelSemanticValidationAnalysis()
        assert a.id
        assert a.name == ""
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        r = OtelSemanticValidationReport()
        assert r.total_records == 0
        assert r.avg_score == 0.0
        assert r.recommendations == []


class TestSemanticValidationEngine:
    @pytest.fixture()
    def engine(self):
        return OtelSemanticValidationEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100
        assert engine._threshold == 50.0
        assert engine._records == []
        assert engine._analyses == []

    def test_add_record(self, engine):
        r = engine.add_record(name="test-attr", service="svc-a", score=75.0)
        assert r.name == "test-attr"
        assert r.score == 75.0
        assert len(engine._records) == 1

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        found = engine.get_record(r.id)
        assert found is not None
        assert found.id == r.id

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nonexistent") is None

    def test_list_records_filter_scope(self, engine):
        engine.add_record(name="a", semantic_scope=SemanticScope.SPAN)
        engine.add_record(name="b", semantic_scope=SemanticScope.METRIC)
        results = engine.list_records(semantic_scope=SemanticScope.SPAN)
        assert len(results) == 1
        assert results[0].name == "a"

    def test_list_records_filter_compliance(self, engine):
        engine.add_record(name="a", compliance_level=ComplianceLevel.FULL)
        engine.add_record(name="b", compliance_level=ComplianceLevel.NONE)
        results = engine.list_records(compliance_level=ComplianceLevel.NONE)
        assert len(results) == 1

    def test_list_records_filter_team(self, engine):
        engine.add_record(name="a", team="platform")
        engine.add_record(name="b", team="security")
        results = engine.list_records(team="platform")
        assert len(results) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="analysis-1", analysis_score=80.0)
        assert a.name == "analysis-1"
        assert len(engine._analyses) == 1

    def test_compute_convention_compliance(self, engine):
        engine.add_record(name="a", service="svc-a", compliance_level=ComplianceLevel.FULL, score=90)
        engine.add_record(name="b", service="svc-a", compliance_level=ComplianceLevel.PARTIAL, score=40)
        results = engine.compute_convention_compliance()
        assert len(results) == 1
        assert results[0]["service"] == "svc-a"
        assert results[0]["fully_compliant"] == 1
        assert results[0]["compliance_pct"] == 50.0

    def test_identify_naming_violations(self, engine):
        engine.add_record(name="ok", compliance_level=ComplianceLevel.FULL, violation_count=0)
        engine.add_record(name="bad", compliance_level=ComplianceLevel.NONE, violation_count=5, attribute_name="http.method")
        violations = engine.identify_naming_violations()
        assert len(violations) == 1
        assert violations[0]["attribute_name"] == "http.method"

    def test_recommend_attribute_fixes(self, engine):
        engine.add_record(name="fix1", compliance_level=ComplianceLevel.PARTIAL, fix_complexity=FixComplexity.TRIVIAL, attribute_name="a.b")
        engine.add_record(name="fix2", compliance_level=ComplianceLevel.NONE, fix_complexity=FixComplexity.COMPLEX, attribute_name="c.d")
        recs = engine.recommend_attribute_fixes()
        assert len(recs) == 2
        assert recs[0]["priority"] == "high"

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", semantic_scope=SemanticScope.SPAN, score=80)
        engine.add_record(name="b", semantic_scope=SemanticScope.SPAN, score=60)
        dist = engine.analyze_distribution()
        assert "span" in dist
        assert dist["span"]["count"] == 2

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=20.0)
        engine.add_record(name="high", score=90.0)
        gaps = engine.identify_gaps()
        assert len(gaps) == 1
        assert gaps[0]["name"] == "low"

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="svc-a", score=30)
        engine.add_record(name="b", service="svc-b", score=90)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "svc-a"

    def test_process_found(self, engine):
        engine.add_record(name="test-key", score=70)
        result = engine.process("test-key")
        assert result["status"] == "processed"
        assert result["count"] == 1

    def test_process_not_found(self, engine):
        result = engine.process("missing")
        assert result["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30, semantic_scope=SemanticScope.SPAN)
        engine.add_record(name="b", score=80, semantic_scope=SemanticScope.METRIC)
        report = engine.generate_report()
        assert isinstance(report, OtelSemanticValidationReport)
        assert report.total_records == 2
        assert report.gap_count == 1

    def test_generate_report_empty(self, engine):
        report = engine.generate_report()
        assert report.total_records == 0
        assert report.avg_score == 0.0

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.add_analysis(name="b")
        result = engine.clear_data()
        assert result["status"] == "cleared"
        assert len(engine._records) == 0
        assert len(engine._analyses) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="svc-a", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_teams"] == 1
        assert stats["unique_services"] == 1


# ========== OtelLogCorrelationEngine ==========


class TestLogCorrelationEnums:
    def test_correlation_status_values(self):
        assert CorrelationStatus.CORRELATED == "correlated"
        assert CorrelationStatus.ORPHANED == "orphaned"
        assert CorrelationStatus.MISSING_CONTEXT == "missing_context"

    def test_log_level_values(self):
        assert LogLevel.TRACE == "trace"
        assert LogLevel.DEBUG == "debug"
        assert LogLevel.INFO == "info"
        assert LogLevel.WARN == "warn"
        assert LogLevel.ERROR == "error"
        assert LogLevel.FATAL == "fatal"

    def test_correlation_quality_values(self):
        assert CorrelationQuality.EXCELLENT == "excellent"
        assert CorrelationQuality.POOR == "poor"


class TestLogCorrelationModels:
    def test_record_defaults(self):
        r = OtelLogCorrelationRecord()
        assert r.correlation_status == CorrelationStatus.CORRELATED
        assert r.log_level == LogLevel.INFO

    def test_analysis_defaults(self):
        a = OtelLogCorrelationAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = OtelLogCorrelationReport()
        assert r.by_log_level == {}


class TestLogCorrelationEngine:
    @pytest.fixture()
    def engine(self):
        return OtelLogCorrelationEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="log-1", service="svc-a", score=60)
        assert r.name == "log-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_status(self, engine):
        engine.add_record(name="a", correlation_status=CorrelationStatus.CORRELATED)
        engine.add_record(name="b", correlation_status=CorrelationStatus.ORPHANED)
        results = engine.list_records(correlation_status=CorrelationStatus.ORPHANED)
        assert len(results) == 1

    def test_list_records_filter_level(self, engine):
        engine.add_record(name="a", log_level=LogLevel.ERROR)
        engine.add_record(name="b", log_level=LogLevel.INFO)
        results = engine.list_records(log_level=LogLevel.ERROR)
        assert len(results) == 1

    def test_list_records_filter_team(self, engine):
        engine.add_record(name="a", team="ops")
        engine.add_record(name="b", team="dev")
        assert len(engine.list_records(team="ops")) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1", analysis_score=70)
        assert a.analysis_score == 70

    def test_compute_correlation_rate(self, engine):
        engine.add_record(name="a", service="svc-a", correlation_status=CorrelationStatus.CORRELATED, score=80)
        engine.add_record(name="b", service="svc-a", correlation_status=CorrelationStatus.ORPHANED, score=30)
        results = engine.compute_correlation_rate()
        assert len(results) == 1
        assert results[0]["correlation_rate"] == 50.0

    def test_identify_orphaned_logs(self, engine):
        engine.add_record(name="ok", correlation_status=CorrelationStatus.CORRELATED)
        engine.add_record(name="orphan", correlation_status=CorrelationStatus.ORPHANED, log_count=100)
        orphaned = engine.identify_orphaned_logs()
        assert len(orphaned) == 1
        assert orphaned[0]["name"] == "orphan"

    def test_recommend_instrumentation_fixes(self, engine):
        engine.add_record(name="a", service="svc-a", correlation_status=CorrelationStatus.ORPHANED)
        engine.add_record(name="b", service="svc-a", correlation_status=CorrelationStatus.CORRELATED)
        recs = engine.recommend_instrumentation_fixes()
        assert len(recs) == 1
        assert "svc-a" in recs[0]["suggestion"]

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        engine.add_record(name="high", score=90)
        gaps = engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=20)
        engine.add_record(name="b", service="s2", score=80)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"

    def test_process_found(self, engine):
        engine.add_record(name="key1", score=60)
        result = engine.process("key1")
        assert result["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        engine.add_record(name="b", score=80)
        report = engine.generate_report()
        assert isinstance(report, OtelLogCorrelationReport)
        assert report.total_records == 2

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ========== CrossSignalCorrelationEngine ==========


class TestCrossSignalEnums:
    def test_signal_type_values(self):
        assert SignalType.TRACE == "trace"
        assert SignalType.METRIC == "metric"
        assert SignalType.LOG == "log"

    def test_correlation_strength_values(self):
        assert CorrelationStrength.STRONG == "strong"
        assert CorrelationStrength.NONE == "none"

    def test_root_cause_confidence_values(self):
        assert RootCauseConfidence.CONFIRMED == "confirmed"
        assert RootCauseConfidence.UNLIKELY == "unlikely"


class TestCrossSignalModels:
    def test_record_defaults(self):
        r = CrossSignalCorrelationRecord()
        assert r.signal_type == SignalType.TRACE
        assert r.correlation_strength == CorrelationStrength.MODERATE

    def test_analysis_defaults(self):
        a = CrossSignalCorrelationAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = CrossSignalCorrelationReport()
        assert r.by_signal_type == {}


class TestCrossSignalEngine:
    @pytest.fixture()
    def engine(self):
        return CrossSignalCorrelationEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="sig-1", service="svc-a", score=70)
        assert r.name == "sig-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_signal(self, engine):
        engine.add_record(name="a", signal_type=SignalType.TRACE)
        engine.add_record(name="b", signal_type=SignalType.LOG)
        results = engine.list_records(signal_type=SignalType.LOG)
        assert len(results) == 1

    def test_list_records_filter_strength(self, engine):
        engine.add_record(name="a", correlation_strength=CorrelationStrength.STRONG)
        engine.add_record(name="b", correlation_strength=CorrelationStrength.WEAK)
        results = engine.list_records(correlation_strength=CorrelationStrength.STRONG)
        assert len(results) == 1

    def test_list_records_filter_team(self, engine):
        engine.add_record(name="a", team="infra")
        engine.add_record(name="b", team="app")
        assert len(engine.list_records(team="infra")) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_correlate_signals(self, engine):
        engine.add_record(name="a", service="svc-a", signal_type=SignalType.TRACE)
        engine.add_record(name="b", service="svc-a", signal_type=SignalType.LOG)
        results = engine.correlate_signals()
        assert len(results) == 1
        assert results[0]["coverage_pct"] < 100

    def test_correlate_signals_full_coverage(self, engine):
        engine.add_record(name="a", service="svc-a", signal_type=SignalType.TRACE)
        engine.add_record(name="b", service="svc-a", signal_type=SignalType.METRIC)
        engine.add_record(name="c", service="svc-a", signal_type=SignalType.LOG)
        results = engine.correlate_signals()
        assert results[0]["coverage_pct"] == 100.0

    def test_identify_causal_chains(self, engine):
        engine.add_record(name="a", correlation_id="corr-1", signal_type=SignalType.TRACE, service="s1", score=80)
        engine.add_record(name="b", correlation_id="corr-1", signal_type=SignalType.LOG, service="s1", score=60)
        chains = engine.identify_causal_chains()
        assert len(chains) == 1
        assert chains[0]["chain_length"] == 2

    def test_identify_causal_chains_single_signal(self, engine):
        engine.add_record(name="a", correlation_id="corr-1", signal_type=SignalType.TRACE)
        engine.add_record(name="b", correlation_id="corr-1", signal_type=SignalType.TRACE)
        chains = engine.identify_causal_chains()
        assert len(chains) == 0

    def test_compute_root_cause_confidence(self, engine):
        engine.add_record(name="a", service="s1", root_cause_confidence=RootCauseConfidence.CONFIRMED)
        engine.add_record(name="b", service="s1", root_cause_confidence=RootCauseConfidence.UNLIKELY)
        results = engine.compute_root_cause_confidence()
        assert len(results) == 1
        assert results[0]["confirmed_count"] == 1

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        engine.add_record(name="high", score=90)
        assert len(engine.identify_gaps()) == 1

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=20)
        engine.add_record(name="b", service="s2", score=80)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"

    def test_process_found(self, engine):
        engine.add_record(name="k1", score=70)
        assert engine.process("k1")["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        engine.add_record(name="b", score=80)
        report = engine.generate_report()
        assert isinstance(report, CrossSignalCorrelationReport)
        assert report.total_records == 2

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_teams"] == 1

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", signal_type=SignalType.TRACE, score=80)
        dist = engine.analyze_distribution()
        assert "trace" in dist

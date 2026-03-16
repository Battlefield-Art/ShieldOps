"""Tests for Phase 139 OTel Metrics Engines (engines 1-3)."""

from __future__ import annotations

import pytest

from shieldops.observability.golden_signals_coverage_engine import (
    CoverageStatus,
    GoldenSignal,
    GoldenSignalsCoverageAnalysis,
    GoldenSignalsCoverageEngine,
    GoldenSignalsCoverageRecord,
    GoldenSignalsCoverageReport,
    SignalQuality,
)
from shieldops.observability.metric_aggregation_optimizer_engine import (
    AggregationMethod,
    MetricAggregationOptimizerAnalysis,
    MetricAggregationOptimizerEngine,
    MetricAggregationOptimizerRecord,
    MetricAggregationOptimizerReport,
    OptimizationOutcome,
    TemporalityType,
)
from shieldops.observability.service_level_indicator_engine import (
    ServiceLevelIndicatorAnalysis,
    ServiceLevelIndicatorEngine,
    ServiceLevelIndicatorRecord,
    ServiceLevelIndicatorReport,
    SLIStatus,
    SLIType,
    ValidationResult,
)

# ============================================================================
# GoldenSignalsCoverageEngine
# ============================================================================


class TestGoldenSignalsCoverageEnums:
    def test_golden_signal_values(self):
        assert GoldenSignal.LATENCY == "latency"
        assert GoldenSignal.TRAFFIC == "traffic"
        assert GoldenSignal.ERRORS == "errors"
        assert GoldenSignal.SATURATION == "saturation"

    def test_coverage_status_values(self):
        assert CoverageStatus.COVERED == "covered"
        assert CoverageStatus.PARTIAL == "partial"
        assert CoverageStatus.MISSING == "missing"

    def test_signal_quality_values(self):
        assert SignalQuality.EXCELLENT == "excellent"
        assert SignalQuality.ADEQUATE == "adequate"
        assert SignalQuality.INSUFFICIENT == "insufficient"


class TestGoldenSignalsCoverageModels:
    def test_record_defaults(self):
        r = GoldenSignalsCoverageRecord()
        assert r.id
        assert r.golden_signal == GoldenSignal.LATENCY
        assert r.coverage_status == CoverageStatus.COVERED
        assert r.signal_quality == SignalQuality.EXCELLENT

    def test_analysis_defaults(self):
        a = GoldenSignalsCoverageAnalysis()
        assert a.id
        assert a.golden_signal == GoldenSignal.LATENCY

    def test_report_defaults(self):
        r = GoldenSignalsCoverageReport()
        assert r.total_records == 0
        assert r.by_golden_signal == {}


class TestGoldenSignalsCoverageEngine:
    @pytest.fixture()
    def engine(self):
        return GoldenSignalsCoverageEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="latency-check", golden_signal=GoldenSignal.LATENCY, score=80.0, service="api"
        )
        assert r.name == "latency-check"
        assert r.golden_signal == GoldenSignal.LATENCY

    def test_get_record(self, engine):
        r = engine.add_record(name="t1", score=10.0, service="svc")
        found = engine.get_record(r.id)
        assert found is not None
        assert found.id == r.id

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nonexistent") is None

    def test_list_records_no_filter(self, engine):
        engine.add_record(name="a", service="s1")
        engine.add_record(name="b", service="s2")
        assert len(engine.list_records()) == 2

    def test_list_records_filter_signal(self, engine):
        engine.add_record(name="a", golden_signal=GoldenSignal.LATENCY)
        engine.add_record(name="b", golden_signal=GoldenSignal.ERRORS)
        res = engine.list_records(golden_signal=GoldenSignal.ERRORS)
        assert len(res) == 1

    def test_list_records_filter_status(self, engine):
        engine.add_record(name="a", coverage_status=CoverageStatus.COVERED)
        engine.add_record(name="b", coverage_status=CoverageStatus.MISSING)
        res = engine.list_records(coverage_status=CoverageStatus.MISSING)
        assert len(res) == 1

    def test_list_records_filter_team(self, engine):
        engine.add_record(name="a", team="alpha")
        engine.add_record(name="b", team="beta")
        res = engine.list_records(team="alpha")
        assert len(res) == 1

    def test_list_records_limit(self, engine):
        for i in range(10):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine.list_records(limit=3)) == 3

    def test_add_analysis(self, engine):
        a = engine.add_analysis(
            name="analysis1", golden_signal=GoldenSignal.TRAFFIC, analysis_score=75.0
        )
        assert a.name == "analysis1"

    def test_ring_buffer_records(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_ring_buffer_analyses(self, engine):
        for i in range(150):
            engine.add_analysis(name=f"a{i}")
        assert len(engine._analyses) == 100

    def test_compute_golden_signal_coverage(self, engine):
        engine.add_record(name="a", golden_signal=GoldenSignal.LATENCY, service="api", score=80.0)
        engine.add_record(name="b", golden_signal=GoldenSignal.ERRORS, service="api", score=60.0)
        result = engine.compute_golden_signal_coverage()
        assert len(result) == 1
        assert result[0]["service"] == "api"
        assert result[0]["coverage_pct"] == 50.0

    def test_compute_golden_signal_coverage_full(self, engine):
        for sig in GoldenSignal:
            engine.add_record(name=f"m-{sig}", golden_signal=sig, service="full", score=90.0)
        result = engine.compute_golden_signal_coverage()
        assert result[0]["coverage_pct"] == 100.0

    def test_identify_uncovered_services(self, engine):
        engine.add_record(name="a", golden_signal=GoldenSignal.LATENCY, service="svc1")
        result = engine.identify_uncovered_services()
        assert len(result) == 1
        assert len(result[0]["missing_signals"]) == 3

    def test_identify_uncovered_empty(self, engine):
        assert engine.identify_uncovered_services() == []

    def test_recommend_instrumentation_missing(self, engine):
        engine.add_record(
            name="m1",
            coverage_status=CoverageStatus.MISSING,
            golden_signal=GoldenSignal.SATURATION,
            service="api",
        )
        recs = engine.recommend_instrumentation()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_instrumentation_insufficient(self, engine):
        engine.add_record(
            name="m1",
            coverage_status=CoverageStatus.COVERED,
            signal_quality=SignalQuality.INSUFFICIENT,
            service="api",
        )
        recs = engine.recommend_instrumentation()
        assert len(recs) == 1
        assert recs[0]["priority"] == "medium"

    def test_recommend_instrumentation_empty(self, engine):
        engine.add_record(
            name="ok",
            coverage_status=CoverageStatus.COVERED,
            signal_quality=SignalQuality.EXCELLENT,
        )
        assert engine.recommend_instrumentation() == []

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", golden_signal=GoldenSignal.LATENCY, score=80.0)
        engine.add_record(name="b", golden_signal=GoldenSignal.LATENCY, score=60.0)
        dist = engine.analyze_distribution()
        assert dist["latency"]["count"] == 2
        assert dist["latency"]["avg_score"] == 70.0

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=20.0, service="s")
        engine.add_record(name="high", score=80.0, service="s")
        gaps = engine.identify_gaps()
        assert len(gaps) == 1
        assert gaps[0]["name"] == "low"

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=30.0)
        engine.add_record(name="b", service="s2", score=90.0)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"

    def test_process_found(self, engine):
        engine.add_record(name="check", service="api", score=70.0)
        result = engine.process("api")
        assert result["status"] == "processed"
        assert result["count"] == 1

    def test_process_not_found(self, engine):
        result = engine.process("nope")
        assert result["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", golden_signal=GoldenSignal.LATENCY, score=30.0, service="s")
        engine.add_record(name="b", golden_signal=GoldenSignal.ERRORS, score=80.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 2
        assert report.gap_count == 1
        assert "latency" in report.by_golden_signal

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="ok", score=90.0, service="s")
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_generate_report_empty(self, engine):
        report = engine.generate_report()
        assert report.total_records == 0

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.add_analysis(name="b")
        result = engine.clear_data()
        assert result["status"] == "cleared"
        assert len(engine._records) == 0
        assert len(engine._analyses) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", golden_signal=GoldenSignal.TRAFFIC, service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1
        assert stats["unique_teams"] == 1
        assert "traffic" in stats["golden_signal_distribution"]


# ============================================================================
# MetricAggregationOptimizerEngine
# ============================================================================


class TestMetricAggregationOptimizerEnums:
    def test_temporality_values(self):
        assert TemporalityType.CUMULATIVE == "cumulative"
        assert TemporalityType.DELTA == "delta"

    def test_aggregation_method_values(self):
        assert AggregationMethod.SUM == "sum"
        assert AggregationMethod.PERCENTILE == "percentile"

    def test_optimization_outcome_values(self):
        assert OptimizationOutcome.REDUCED_CARDINALITY == "reduced_cardinality"
        assert OptimizationOutcome.LOWER_COST == "lower_cost"


class TestMetricAggregationOptimizerModels:
    def test_record_defaults(self):
        r = MetricAggregationOptimizerRecord()
        assert r.temporality_type == TemporalityType.CUMULATIVE
        assert r.aggregation_method == AggregationMethod.SUM

    def test_analysis_defaults(self):
        a = MetricAggregationOptimizerAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = MetricAggregationOptimizerReport()
        assert r.total_records == 0


class TestMetricAggregationOptimizerEngine:
    @pytest.fixture()
    def engine(self):
        return MetricAggregationOptimizerEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(
            name="m1", temporality_type=TemporalityType.DELTA, score=70.0, service="api"
        )
        assert r.temporality_type == TemporalityType.DELTA

    def test_get_record(self, engine):
        r = engine.add_record(name="m1", service="s")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("x") is None

    def test_list_records_filter_temporality(self, engine):
        engine.add_record(name="a", temporality_type=TemporalityType.CUMULATIVE)
        engine.add_record(name="b", temporality_type=TemporalityType.DELTA)
        res = engine.list_records(temporality_type=TemporalityType.DELTA)
        assert len(res) == 1

    def test_list_records_filter_method(self, engine):
        engine.add_record(name="a", aggregation_method=AggregationMethod.SUM)
        engine.add_record(name="b", aggregation_method=AggregationMethod.MAX)
        res = engine.list_records(aggregation_method=AggregationMethod.MAX)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1", analysis_score=60.0)
        assert a.name == "a1"

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_evaluate_aggregation_efficiency(self, engine):
        engine.add_record(name="a", service="api", score=80.0, cardinality=100)
        engine.add_record(name="b", service="api", score=30.0, cardinality=200)
        result = engine.evaluate_aggregation_efficiency()
        assert len(result) == 1
        assert result[0]["service"] == "api"
        assert result[0]["total_cardinality"] == 300

    def test_evaluate_aggregation_efficiency_empty(self, engine):
        assert engine.evaluate_aggregation_efficiency() == []

    def test_detect_temporal_misalignment(self, engine):
        engine.add_record(name="a", service="api", temporality_type=TemporalityType.CUMULATIVE)
        engine.add_record(name="b", service="api", temporality_type=TemporalityType.DELTA)
        issues = engine.detect_temporal_misalignment()
        assert len(issues) == 1
        assert issues[0]["issue"] == "mixed_temporality"

    def test_detect_temporal_misalignment_none(self, engine):
        engine.add_record(name="a", service="api", temporality_type=TemporalityType.CUMULATIVE)
        engine.add_record(name="b", service="api", temporality_type=TemporalityType.CUMULATIVE)
        assert engine.detect_temporal_misalignment() == []

    def test_recommend_rollup_strategy_high_cardinality(self, engine):
        engine.add_record(name="m1", service="api", cardinality=5000, score=80.0)
        recs = engine.recommend_rollup_strategy()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_rollup_strategy_low_score(self, engine):
        engine.add_record(name="m1", service="api", cardinality=100, score=20.0)
        recs = engine.recommend_rollup_strategy()
        assert len(recs) == 1
        assert recs[0]["priority"] == "medium"

    def test_recommend_rollup_strategy_empty(self, engine):
        engine.add_record(name="ok", cardinality=50, score=80.0)
        assert engine.recommend_rollup_strategy() == []

    def test_process(self, engine):
        engine.add_record(name="m1", service="api", score=60.0)
        result = engine.process("api")
        assert result["count"] == 1

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================================
# ServiceLevelIndicatorEngine
# ============================================================================


class TestServiceLevelIndicatorEnums:
    def test_sli_type_values(self):
        assert SLIType.AVAILABILITY == "availability"
        assert SLIType.LATENCY == "latency"
        assert SLIType.THROUGHPUT == "throughput"
        assert SLIType.ERROR_RATE == "error_rate"

    def test_sli_status_values(self):
        assert SLIStatus.MEETING == "meeting"
        assert SLIStatus.AT_RISK == "at_risk"
        assert SLIStatus.BREACHING == "breaching"

    def test_validation_result_values(self):
        assert ValidationResult.VALID == "valid"
        assert ValidationResult.MISCONFIGURED == "misconfigured"
        assert ValidationResult.STALE == "stale"


class TestServiceLevelIndicatorModels:
    def test_record_defaults(self):
        r = ServiceLevelIndicatorRecord()
        assert r.sli_type == SLIType.AVAILABILITY
        assert r.target_value == 99.9

    def test_analysis_defaults(self):
        a = ServiceLevelIndicatorAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = ServiceLevelIndicatorReport()
        assert r.total_records == 0


class TestServiceLevelIndicatorEngine:
    @pytest.fixture()
    def engine(self):
        return ServiceLevelIndicatorEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._threshold == 50.0

    def test_add_record(self, engine):
        r = engine.add_record(name="sli1", sli_type=SLIType.LATENCY, score=80.0, service="api")
        assert r.sli_type == SLIType.LATENCY

    def test_get_record(self, engine):
        r = engine.add_record(name="sli1", service="s")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("x") is None

    def test_list_records_filter_type(self, engine):
        engine.add_record(name="a", sli_type=SLIType.AVAILABILITY)
        engine.add_record(name="b", sli_type=SLIType.LATENCY)
        res = engine.list_records(sli_type=SLIType.LATENCY)
        assert len(res) == 1

    def test_list_records_filter_status(self, engine):
        engine.add_record(name="a", sli_status=SLIStatus.MEETING)
        engine.add_record(name="b", sli_status=SLIStatus.BREACHING)
        res = engine.list_records(sli_status=SLIStatus.BREACHING)
        assert len(res) == 1

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1", sli_type=SLIType.THROUGHPUT)
        assert a.sli_type == SLIType.THROUGHPUT

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r{i}", service="s")
        assert len(engine._records) == 100

    def test_validate_sli_definitions_valid(self, engine):
        engine.add_record(
            name="sli1", validation_result=ValidationResult.VALID, target_value=99.9, service="api"
        )
        results = engine.validate_sli_definitions()
        assert len(results) == 1
        assert results[0]["is_valid"] is True

    def test_validate_sli_definitions_misconfigured(self, engine):
        engine.add_record(
            name="sli1", validation_result=ValidationResult.MISCONFIGURED, service="api"
        )
        results = engine.validate_sli_definitions()
        assert results[0]["is_valid"] is False

    def test_validate_sli_definitions_stale(self, engine):
        engine.add_record(name="sli1", validation_result=ValidationResult.STALE, service="api")
        results = engine.validate_sli_definitions()
        assert not results[0]["is_valid"]

    def test_validate_sli_definitions_invalid_target(self, engine):
        engine.add_record(name="sli1", target_value=0, service="api")
        results = engine.validate_sli_definitions()
        assert not results[0]["is_valid"]

    def test_detect_sli_drift(self, engine):
        engine.add_record(
            name="sli1",
            target_value=99.9,
            actual_value=90.0,
            sli_status=SLIStatus.BREACHING,
            service="api",
        )
        drifts = engine.detect_sli_drift()
        assert len(drifts) == 1
        assert drifts[0]["drift_pct"] > 5.0

    def test_detect_sli_drift_no_drift(self, engine):
        engine.add_record(
            name="sli1",
            target_value=99.9,
            actual_value=99.8,
            sli_status=SLIStatus.MEETING,
            service="api",
        )
        drifts = engine.detect_sli_drift()
        assert len(drifts) == 0

    def test_recommend_sli_improvements_breaching(self, engine):
        engine.add_record(name="sli1", sli_status=SLIStatus.BREACHING, service="api")
        recs = engine.recommend_sli_improvements()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_sli_improvements_misconfigured(self, engine):
        engine.add_record(
            name="sli1",
            sli_status=SLIStatus.MEETING,
            validation_result=ValidationResult.MISCONFIGURED,
            service="api",
        )
        recs = engine.recommend_sli_improvements()
        assert len(recs) == 1
        assert recs[0]["priority"] == "medium"

    def test_recommend_sli_improvements_empty(self, engine):
        engine.add_record(
            name="ok", sli_status=SLIStatus.MEETING, validation_result=ValidationResult.VALID
        )
        assert engine.recommend_sli_improvements() == []

    def test_process(self, engine):
        engine.add_record(name="sli1", service="api", score=70.0)
        result = engine.process("api")
        assert result["count"] == 1

    def test_process_not_found(self, engine):
        result = engine.process("nope")
        assert result["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=30.0, service="s")
        report = engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="ok", score=90.0, service="s")
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_clear_data(self, engine):
        engine.add_record(name="a", service="s")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", sli_type=SLIType.LATENCY, service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert "latency" in stats["sli_type_distribution"]

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", sli_type=SLIType.AVAILABILITY, score=80.0)
        dist = engine.analyze_distribution()
        assert "availability" in dist

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=20.0, service="s")
        gaps = engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=30.0)
        engine.add_record(name="b", service="s2", score=90.0)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"

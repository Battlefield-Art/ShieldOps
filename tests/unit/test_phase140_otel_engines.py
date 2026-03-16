"""Tests for Phase 140 OTel Engines (engines 1-3)."""

from __future__ import annotations

from shieldops.observability.log_pipeline_quality_engine import (
    LogPipelineQualityEngine,
    LogQualityDimension,
    PipelineIssue,
    QualityGrade,
)
from shieldops.observability.trace_log_correlation_quality_engine import (
    CorrelationGap,
    CorrelationMethod,
    InstrumentationStatus,
    TraceLogCorrelationQualityEngine,
)
from shieldops.observability.unified_telemetry_cost_engine import (
    CostDriver,
    CostTrend,
    TelemetrySignal,
    UnifiedTelemetryCostEngine,
)

# ============================================================
# LogPipelineQualityEngine Tests
# ============================================================


class TestLogPipelineQualityEnums:
    def test_log_quality_dimension_values(self) -> None:
        assert LogQualityDimension.PARSE_RATE == "parse_rate"
        assert LogQualityDimension.FORMAT_CONSISTENCY == "format_consistency"
        assert LogQualityDimension.ENRICHMENT_COVERAGE == "enrichment_coverage"

    def test_quality_grade_values(self) -> None:
        assert QualityGrade.EXCELLENT == "excellent"
        assert QualityGrade.GOOD == "good"
        assert QualityGrade.FAIR == "fair"
        assert QualityGrade.POOR == "poor"

    def test_pipeline_issue_values(self) -> None:
        assert PipelineIssue.PARSE_FAILURE == "parse_failure"
        assert PipelineIssue.MISSING_FIELDS == "missing_fields"
        assert PipelineIssue.FORMAT_MISMATCH == "format_mismatch"


class TestLogPipelineQualityEngine:
    def setup_method(self) -> None:
        self.engine = LogPipelineQualityEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100
        assert self.engine._threshold == 50.0
        assert len(self.engine._records) == 0

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="test", score=80.0, service="svc-a")
        assert r.name == "test"
        assert r.score == 80.0
        assert len(self.engine._records) == 1

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="t1",
            dimension=LogQualityDimension.FORMAT_CONSISTENCY,
            grade=QualityGrade.POOR,
            issue=PipelineIssue.FORMAT_MISMATCH,
            score=20.0,
        )
        assert r.dimension == LogQualityDimension.FORMAT_CONSISTENCY
        assert r.grade == QualityGrade.POOR
        assert r.issue == PipelineIssue.FORMAT_MISMATCH

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}", score=float(i))
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find-me", score=70.0)
        found = self.engine.get_record(r.id)
        assert found is not None
        assert found.name == "find-me"

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nonexistent") is None

    def test_list_records_no_filter(self) -> None:
        self.engine.add_record(name="a", score=10.0)
        self.engine.add_record(name="b", score=20.0)
        assert len(self.engine.list_records()) == 2

    def test_list_records_filter_dimension(self) -> None:
        self.engine.add_record(name="a", dimension=LogQualityDimension.PARSE_RATE)
        self.engine.add_record(name="b", dimension=LogQualityDimension.ENRICHMENT_COVERAGE)
        result = self.engine.list_records(dimension=LogQualityDimension.PARSE_RATE)
        assert len(result) == 1

    def test_list_records_filter_grade(self) -> None:
        self.engine.add_record(name="a", grade=QualityGrade.EXCELLENT)
        self.engine.add_record(name="b", grade=QualityGrade.POOR)
        result = self.engine.list_records(grade=QualityGrade.POOR)
        assert len(result) == 1

    def test_list_records_filter_team(self) -> None:
        self.engine.add_record(name="a", team="alpha")
        self.engine.add_record(name="b", team="beta")
        result = self.engine.list_records(team="alpha")
        assert len(result) == 1

    def test_list_records_limit(self) -> None:
        for i in range(10):
            self.engine.add_record(name=f"r{i}")
        result = self.engine.list_records(limit=3)
        assert len(result) == 3

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=75.0)
        assert a.name == "a1"
        assert len(self.engine._analyses) == 1

    def test_compute_pipeline_quality_score(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", score=90.0, dimension=LogQualityDimension.PARSE_RATE
        )
        self.engine.add_record(
            name="r2", service="svc-a", score=70.0, dimension=LogQualityDimension.FORMAT_CONSISTENCY
        )
        result = self.engine.compute_pipeline_quality_score()
        assert len(result) == 1
        assert result[0]["service"] == "svc-a"
        assert result[0]["overall_score"] == 80.0

    def test_compute_pipeline_quality_score_grade(self) -> None:
        self.engine.add_record(name="r1", service="svc-a", score=95.0)
        result = self.engine.compute_pipeline_quality_score()
        assert result[0]["grade"] == "excellent"

    def test_identify_parsing_failures(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", issue=PipelineIssue.PARSE_FAILURE, failure_rate=0.6
        )
        self.engine.add_record(
            name="r2", service="svc-b", issue=PipelineIssue.MISSING_FIELDS, failure_rate=0.3
        )
        result = self.engine.identify_parsing_failures()
        assert len(result) == 1
        assert result[0]["priority"] == "high"

    def test_identify_parsing_failures_priority(self) -> None:
        self.engine.add_record(
            name="r1", issue=PipelineIssue.PARSE_FAILURE, failure_rate=0.1, service="svc"
        )
        result = self.engine.identify_parsing_failures()
        assert result[0]["priority"] == "low"

    def test_recommend_format_standardization(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", score=20.0, issue=PipelineIssue.FORMAT_MISMATCH
        )
        self.engine.add_record(
            name="r2", service="svc-a", score=25.0, issue=PipelineIssue.MISSING_FIELDS
        )
        result = self.engine.recommend_format_standardization()
        assert len(result) == 1
        assert result[0]["priority"] == "high"

    def test_recommend_format_standardization_empty(self) -> None:
        self.engine.add_record(name="r1", issue=PipelineIssue.PARSE_FAILURE, service="svc")
        result = self.engine.recommend_format_standardization()
        assert len(result) == 0

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", dimension=LogQualityDimension.PARSE_RATE, score=80.0)
        self.engine.add_record(name="r2", dimension=LogQualityDimension.PARSE_RATE, score=60.0)
        result = self.engine.analyze_distribution()
        assert "parse_rate" in result
        assert result["parse_rate"]["count"] == 2

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        self.engine.add_record(name="high", score=90.0, service="svc")
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1
        assert gaps[0]["name"] == "low"

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="svc-a", score=30.0)
        self.engine.add_record(name="r2", service="svc-b", score=80.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "svc-a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="test-key", score=60.0)
        result = self.engine.process("test-key")
        assert result["status"] == "processed"
        assert result["count"] == 1

    def test_process_not_found(self) -> None:
        result = self.engine.process("missing")
        assert result["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        self.engine.add_record(name="r2", score=80.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 2
        assert report.gap_count == 1

    def test_generate_report_healthy(self) -> None:
        self.engine.add_record(name="r1", score=90.0, service="svc")
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1", score=50.0)
        self.engine.add_analysis(name="a1")
        result = self.engine.clear_data()
        assert result["status"] == "cleared"
        assert len(self.engine._records) == 0
        assert len(self.engine._analyses) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc-a", team="t1", score=50.0)
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1
        assert stats["unique_teams"] == 1


# ============================================================
# TraceLogCorrelationQualityEngine Tests
# ============================================================


class TestTraceLogCorrelationQualityEnums:
    def test_correlation_method_values(self) -> None:
        assert CorrelationMethod.TRACE_ID_INJECTION == "trace_id_injection"
        assert CorrelationMethod.W3C_TRACEPARENT == "w3c_traceparent"
        assert CorrelationMethod.B3_PROPAGATION == "b3_propagation"

    def test_correlation_gap_values(self) -> None:
        assert CorrelationGap.NO_TRACE_ID == "no_trace_id"
        assert CorrelationGap.NO_SPAN_ID == "no_span_id"
        assert CorrelationGap.MISMATCHED_SERVICE == "mismatched_service"

    def test_instrumentation_status_values(self) -> None:
        assert InstrumentationStatus.AUTO == "auto"
        assert InstrumentationStatus.MANUAL == "manual"
        assert InstrumentationStatus.MISSING == "missing"


class TestTraceLogCorrelationQualityEngine:
    def setup_method(self) -> None:
        self.engine = TraceLogCorrelationQualityEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100
        assert self.engine._threshold == 50.0

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="test", score=80.0, service="svc-a")
        assert r.name == "test"
        assert len(self.engine._records) == 1

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="t1",
            method=CorrelationMethod.W3C_TRACEPARENT,
            gap=CorrelationGap.NO_SPAN_ID,
            status=InstrumentationStatus.MISSING,
        )
        assert r.method == CorrelationMethod.W3C_TRACEPARENT
        assert r.gap == CorrelationGap.NO_SPAN_ID
        assert r.status == InstrumentationStatus.MISSING

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}", score=float(i))
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find-me")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_method(self) -> None:
        self.engine.add_record(name="a", method=CorrelationMethod.B3_PROPAGATION)
        self.engine.add_record(name="b", method=CorrelationMethod.W3C_TRACEPARENT)
        result = self.engine.list_records(method=CorrelationMethod.B3_PROPAGATION)
        assert len(result) == 1

    def test_list_records_filter_status(self) -> None:
        self.engine.add_record(name="a", status=InstrumentationStatus.AUTO)
        self.engine.add_record(name="b", status=InstrumentationStatus.MISSING)
        result = self.engine.list_records(status=InstrumentationStatus.MISSING)
        assert len(result) == 1

    def test_list_records_filter_team(self) -> None:
        self.engine.add_record(name="a", team="t1")
        self.engine.add_record(name="b", team="t2")
        result = self.engine.list_records(team="t1")
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=60.0)
        assert a.analysis_score == 60.0

    def test_measure_correlation_coverage(self) -> None:
        self.engine.add_record(name="r1", service="svc-a", correlation_pct=95.0)
        self.engine.add_record(name="r2", service="svc-a", correlation_pct=85.0)
        result = self.engine.measure_correlation_coverage()
        assert len(result) == 1
        assert result[0]["avg_correlation_pct"] == 90.0
        assert result[0]["coverage_grade"] == "excellent"

    def test_measure_correlation_coverage_poor(self) -> None:
        self.engine.add_record(name="r1", service="svc-b", correlation_pct=20.0)
        result = self.engine.measure_correlation_coverage()
        assert result[0]["coverage_grade"] == "poor"

    def test_identify_correlation_gaps(self) -> None:
        self.engine.add_record(
            name="r1",
            service="svc-a",
            status=InstrumentationStatus.MISSING,
            gap=CorrelationGap.NO_TRACE_ID,
            correlation_pct=10.0,
        )
        result = self.engine.identify_correlation_gaps()
        assert len(result) == 1
        assert result[0]["service"] == "svc-a"

    def test_identify_correlation_gaps_empty(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", status=InstrumentationStatus.AUTO, correlation_pct=90.0
        )
        result = self.engine.identify_correlation_gaps()
        assert len(result) == 0

    def test_recommend_instrumentation_changes(self) -> None:
        self.engine.add_record(name="r1", service="svc-a", status=InstrumentationStatus.MISSING)
        result = self.engine.recommend_instrumentation_changes()
        assert len(result) >= 1
        assert result[0]["priority"] == "high"

    def test_recommend_instrumentation_changes_manual(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-b", status=InstrumentationStatus.MANUAL, correlation_pct=40.0
        )
        result = self.engine.recommend_instrumentation_changes()
        assert any(r["issue"] == "low_manual_correlation" for r in result)

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", method=CorrelationMethod.W3C_TRACEPARENT, score=80.0)
        result = self.engine.analyze_distribution()
        assert "w3c_traceparent" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=30.0)
        self.engine.add_record(name="r2", service="b", score=80.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="key1", score=70.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_process_not_found(self) -> None:
        result = self.engine.process("nope")
        assert result["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_generate_report_healthy(self) -> None:
        self.engine.add_record(name="r1", score=90.0, service="svc")
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================
# UnifiedTelemetryCostEngine Tests
# ============================================================


class TestUnifiedTelemetryCostEnums:
    def test_telemetry_signal_values(self) -> None:
        assert TelemetrySignal.TRACES == "traces"
        assert TelemetrySignal.METRICS == "metrics"
        assert TelemetrySignal.LOGS == "logs"

    def test_cost_driver_values(self) -> None:
        assert CostDriver.VOLUME == "volume"
        assert CostDriver.CARDINALITY == "cardinality"
        assert CostDriver.RETENTION == "retention"
        assert CostDriver.EGRESS == "egress"

    def test_cost_trend_values(self) -> None:
        assert CostTrend.INCREASING == "increasing"
        assert CostTrend.STABLE == "stable"
        assert CostTrend.DECREASING == "decreasing"


class TestUnifiedTelemetryCostEngine:
    def setup_method(self) -> None:
        self.engine = UnifiedTelemetryCostEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="test", score=80.0, cost_usd=100.0)
        assert r.cost_usd == 100.0
        assert len(self.engine._records) == 1

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="t1",
            signal=TelemetrySignal.LOGS,
            driver=CostDriver.EGRESS,
            trend=CostTrend.INCREASING,
        )
        assert r.signal == TelemetrySignal.LOGS
        assert r.driver == CostDriver.EGRESS
        assert r.trend == CostTrend.INCREASING

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_signal(self) -> None:
        self.engine.add_record(name="a", signal=TelemetrySignal.TRACES)
        self.engine.add_record(name="b", signal=TelemetrySignal.LOGS)
        result = self.engine.list_records(signal=TelemetrySignal.LOGS)
        assert len(result) == 1

    def test_list_records_filter_driver(self) -> None:
        self.engine.add_record(name="a", driver=CostDriver.VOLUME)
        self.engine.add_record(name="b", driver=CostDriver.RETENTION)
        result = self.engine.list_records(driver=CostDriver.RETENTION)
        assert len(result) == 1

    def test_list_records_filter_team(self) -> None:
        self.engine.add_record(name="a", team="t1")
        self.engine.add_record(name="b", team="t2")
        result = self.engine.list_records(team="t1")
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=80.0)
        assert a.analysis_score == 80.0

    def test_compute_cost_by_signal(self) -> None:
        self.engine.add_record(
            name="r1", signal=TelemetrySignal.TRACES, cost_usd=100.0, service="svc"
        )
        self.engine.add_record(
            name="r2", signal=TelemetrySignal.LOGS, cost_usd=200.0, service="svc"
        )
        result = self.engine.compute_cost_by_signal()
        assert len(result) == 2
        assert result[0]["total_cost_usd"] == 200.0  # logs first (higher)

    def test_compute_cost_by_signal_pct(self) -> None:
        self.engine.add_record(
            name="r1", signal=TelemetrySignal.TRACES, cost_usd=50.0, service="svc"
        )
        self.engine.add_record(
            name="r2", signal=TelemetrySignal.TRACES, cost_usd=50.0, service="svc"
        )
        result = self.engine.compute_cost_by_signal()
        assert result[0]["pct_of_total"] == 100.0

    def test_identify_cost_drivers(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", driver=CostDriver.VOLUME, cost_usd=1500.0, volume_gb=500.0
        )
        result = self.engine.identify_cost_drivers()
        assert len(result) == 1
        assert result[0]["priority"] == "high"

    def test_identify_cost_drivers_low(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", driver=CostDriver.VOLUME, cost_usd=10.0, volume_gb=5.0
        )
        result = self.engine.identify_cost_drivers()
        assert result[0]["priority"] == "low"

    def test_recommend_cost_optimizations(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", trend=CostTrend.INCREASING, cost_usd=500.0
        )
        result = self.engine.recommend_cost_optimizations()
        assert len(result) >= 1
        assert result[0]["priority"] == "high"

    def test_recommend_cost_optimizations_volume(self) -> None:
        self.engine.add_record(
            name="r1",
            service="svc-b",
            driver=CostDriver.VOLUME,
            volume_gb=200.0,
            trend=CostTrend.STABLE,
        )
        result = self.engine.recommend_cost_optimizations()
        assert any(r["issue"] == "high_volume" for r in result)

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", signal=TelemetrySignal.METRICS, score=70.0)
        result = self.engine.analyze_distribution()
        assert "metrics" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=20.0)
        self.engine.add_record(name="r2", service="b", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="k1", score=60.0)
        result = self.engine.process("k1")
        assert result["status"] == "processed"

    def test_process_not_found(self) -> None:
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_generate_report_healthy(self) -> None:
        self.engine.add_record(name="r1", score=90.0, service="svc")
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1

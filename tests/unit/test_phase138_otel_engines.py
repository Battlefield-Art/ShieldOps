"""Tests for Phase 138 OTel engines (tail sampling, batch processor, exporter reliability)."""

from __future__ import annotations

import pytest

from shieldops.observability.tail_sampling_policy_engine import (
    PolicyDecision,
    PolicyEffectiveness,
    SamplingCriteria,
    TailSamplingPolicyEngine,
    TailSamplingPolicyRecord,
    TailSamplingPolicyAnalysis,
    TailSamplingPolicyReport,
)
from shieldops.observability.otel_batch_processor_engine import (
    BatchStatus,
    QueuePressure,
    TuningAction,
    OtelBatchProcessorEngine,
    OtelBatchProcessorRecord,
    OtelBatchProcessorAnalysis,
    OtelBatchProcessorReport,
)
from shieldops.observability.otel_exporter_reliability_engine import (
    ExporterHealth,
    RetryOutcome,
    BackendType,
    OtelExporterReliabilityEngine,
    OtelExporterReliabilityRecord,
    OtelExporterReliabilityAnalysis,
    OtelExporterReliabilityReport,
)


# =============================================================================
# TailSamplingPolicyEngine Tests
# =============================================================================


class TestTailSamplingPolicyEnums:
    def test_policy_decision_values(self):
        assert PolicyDecision.ALWAYS_SAMPLE == "always_sample"
        assert PolicyDecision.PROBABILISTIC == "probabilistic"
        assert PolicyDecision.RATE_LIMIT == "rate_limit"

    def test_sampling_criteria_values(self):
        assert SamplingCriteria.LATENCY == "latency"
        assert SamplingCriteria.ERROR == "error"
        assert SamplingCriteria.ATTRIBUTE == "attribute"
        assert SamplingCriteria.COMPOSITE == "composite"

    def test_policy_effectiveness_values(self):
        assert PolicyEffectiveness.OPTIMAL == "optimal"
        assert PolicyEffectiveness.OVERSAMPLING == "oversampling"
        assert PolicyEffectiveness.UNDERSAMPLING == "undersampling"


class TestTailSamplingPolicyModels:
    def test_record_defaults(self):
        r = TailSamplingPolicyRecord()
        assert r.id
        assert r.policy_decision == PolicyDecision.ALWAYS_SAMPLE
        assert r.sampling_criteria == SamplingCriteria.LATENCY
        assert r.policy_effectiveness == PolicyEffectiveness.OPTIMAL
        assert r.score == 0.0

    def test_analysis_defaults(self):
        a = TailSamplingPolicyAnalysis()
        assert a.id
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = TailSamplingPolicyReport()
        assert rp.total_records == 0
        assert rp.recommendations == []


class TestTailSamplingPolicyEngine:
    def setup_method(self):
        self.engine = TailSamplingPolicyEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100
        assert self.engine._threshold == 50.0
        assert len(self.engine._records) == 0

    def test_add_record(self):
        r = self.engine.add_record(name="policy-1", score=75.0, service="svc-a")
        assert r.name == "policy-1"
        assert r.score == 75.0
        assert len(self.engine._records) == 1

    def test_get_record(self):
        r = self.engine.add_record(name="p1", score=60.0)
        found = self.engine.get_record(r.id)
        assert found is not None
        assert found.name == "p1"

    def test_get_record_not_found(self):
        assert self.engine.get_record("nonexistent") is None

    def test_list_records_filter_by_policy_decision(self):
        self.engine.add_record(name="a", policy_decision=PolicyDecision.ALWAYS_SAMPLE)
        self.engine.add_record(name="b", policy_decision=PolicyDecision.PROBABILISTIC)
        results = self.engine.list_records(policy_decision=PolicyDecision.ALWAYS_SAMPLE)
        assert len(results) == 1
        assert results[0].name == "a"

    def test_list_records_filter_by_team(self):
        self.engine.add_record(name="a", team="alpha")
        self.engine.add_record(name="b", team="beta")
        results = self.engine.list_records(team="alpha")
        assert len(results) == 1

    def test_list_records_limit(self):
        for i in range(10):
            self.engine.add_record(name=f"p{i}")
        results = self.engine.list_records(limit=3)
        assert len(results) == 3

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test", analysis_score=80.0)
        assert a.name == "test"
        assert len(self.engine._analyses) == 1

    def test_ring_buffer_eviction(self):
        engine = TailSamplingPolicyEngine(max_records=5)
        for i in range(10):
            engine.add_record(name=f"p{i}")
        assert len(engine._records) == 5
        assert engine._records[0].name == "p5"

    def test_evaluate_policy_effectiveness(self):
        self.engine.add_record(
            name="policy-x", score=80.0, spans_evaluated=1000, spans_sampled=100
        )
        self.engine.add_record(
            name="policy-x", score=60.0, spans_evaluated=2000, spans_sampled=200
        )
        results = self.engine.evaluate_policy_effectiveness()
        assert len(results) == 1
        assert results[0]["policy_name"] == "policy-x"
        assert results[0]["total_evaluated"] == 3000

    def test_evaluate_policy_effectiveness_empty(self):
        assert self.engine.evaluate_policy_effectiveness() == []

    def test_detect_oversampled_services(self):
        self.engine.add_record(
            name="p1",
            service="svc-a",
            policy_effectiveness=PolicyEffectiveness.OVERSAMPLING,
            spans_evaluated=500,
            spans_sampled=400,
        )
        self.engine.add_record(
            name="p2",
            service="svc-b",
            policy_effectiveness=PolicyEffectiveness.OPTIMAL,
        )
        results = self.engine.detect_oversampled_services()
        assert len(results) == 1
        assert results[0]["service"] == "svc-a"
        assert results[0]["recommendation"] == "reduce_sample_rate"

    def test_detect_oversampled_services_empty(self):
        assert self.engine.detect_oversampled_services() == []

    def test_recommend_policy_adjustments_oversampling(self):
        self.engine.add_record(
            name="p1",
            service="svc-a",
            policy_effectiveness=PolicyEffectiveness.OVERSAMPLING,
            sample_rate=0.9,
        )
        results = self.engine.recommend_policy_adjustments()
        assert len(results) == 1
        assert results[0]["issue"] == "oversampling"

    def test_recommend_policy_adjustments_undersampling(self):
        self.engine.add_record(
            name="p1",
            service="svc-a",
            policy_effectiveness=PolicyEffectiveness.UNDERSAMPLING,
            sample_rate=0.01,
        )
        results = self.engine.recommend_policy_adjustments()
        assert len(results) == 1
        assert results[0]["issue"] == "undersampling"
        assert results[0]["priority"] == "high"

    def test_recommend_policy_adjustments_low_score(self):
        self.engine.add_record(
            name="p1",
            service="svc-a",
            policy_effectiveness=PolicyEffectiveness.OPTIMAL,
            score=10.0,
        )
        results = self.engine.recommend_policy_adjustments()
        assert len(results) == 1
        assert results[0]["issue"] == "low_score"

    def test_process_found(self):
        self.engine.add_record(name="test-key", score=60.0)
        result = self.engine.process("test-key")
        assert result["status"] == "processed"
        assert result["count"] == 1

    def test_process_not_found(self):
        result = self.engine.process("missing")
        assert result["status"] == "not_found"

    def test_identify_gaps(self):
        self.engine.add_record(name="low", score=10.0)
        self.engine.add_record(name="high", score=90.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1
        assert gaps[0]["name"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(name="a", policy_decision=PolicyDecision.ALWAYS_SAMPLE, score=80.0)
        self.engine.add_record(name="b", policy_decision=PolicyDecision.PROBABILISTIC, score=60.0)
        dist = self.engine.analyze_distribution()
        assert "always_sample" in dist
        assert "probabilistic" in dist

    def test_rank_by_score(self):
        self.engine.add_record(name="a", service="svc-low", score=20.0)
        self.engine.add_record(name="b", service="svc-high", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "svc-low"

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        self.engine.add_record(name="b", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 2
        assert report.gap_count == 1

    def test_generate_report_healthy(self):
        self.engine.add_record(name="a", score=90.0)
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_get_stats(self):
        self.engine.add_record(name="a", service="svc-a", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_teams"] == 1
        assert stats["unique_services"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.add_analysis(name="b")
        result = self.engine.clear_data()
        assert result["status"] == "cleared"
        assert len(self.engine._records) == 0
        assert len(self.engine._analyses) == 0


# =============================================================================
# OtelBatchProcessorEngine Tests
# =============================================================================


class TestOtelBatchProcessorEnums:
    def test_batch_status_values(self):
        assert BatchStatus.HEALTHY == "healthy"
        assert BatchStatus.FULL == "full"
        assert BatchStatus.DROPPING == "dropping"
        assert BatchStatus.STALLED == "stalled"

    def test_queue_pressure_values(self):
        assert QueuePressure.LOW == "low"
        assert QueuePressure.MODERATE == "moderate"
        assert QueuePressure.HIGH == "high"
        assert QueuePressure.CRITICAL == "critical"

    def test_tuning_action_values(self):
        assert TuningAction.INCREASE_BATCH_SIZE == "increase_batch_size"
        assert TuningAction.DECREASE_TIMEOUT == "decrease_timeout"
        assert TuningAction.ADD_MEMORY == "add_memory"
        assert TuningAction.SCALE_OUT == "scale_out"


class TestOtelBatchProcessorModels:
    def test_record_defaults(self):
        r = OtelBatchProcessorRecord()
        assert r.batch_size == 512
        assert r.queue_capacity == 2048

    def test_analysis_defaults(self):
        a = OtelBatchProcessorAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = OtelBatchProcessorReport()
        assert rp.total_records == 0


class TestOtelBatchProcessorEngine:
    def setup_method(self):
        self.engine = OtelBatchProcessorEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="bp-1", score=70.0, service="svc-a")
        assert r.name == "bp-1"
        assert len(self.engine._records) == 1

    def test_get_record(self):
        r = self.engine.add_record(name="bp-1")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("nope") is None

    def test_list_records_filter(self):
        self.engine.add_record(name="a", batch_status=BatchStatus.HEALTHY)
        self.engine.add_record(name="b", batch_status=BatchStatus.DROPPING)
        results = self.engine.list_records(batch_status=BatchStatus.DROPPING)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_ring_buffer(self):
        engine = OtelBatchProcessorEngine(max_records=3)
        for i in range(7):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 3

    def test_detect_batch_pressure(self):
        self.engine.add_record(
            name="p1",
            service="svc-a",
            queue_pressure=QueuePressure.HIGH,
            dropped_spans=50,
            queue_depth=1800,
            queue_capacity=2048,
        )
        results = self.engine.detect_batch_pressure()
        assert len(results) == 1
        assert results[0]["service"] == "svc-a"
        assert results[0]["total_dropped_spans"] == 50

    def test_detect_batch_pressure_no_issues(self):
        self.engine.add_record(
            name="p1",
            service="svc-a",
            queue_pressure=QueuePressure.LOW,
            dropped_spans=0,
        )
        results = self.engine.detect_batch_pressure()
        assert len(results) == 0

    def test_compute_optimal_batch_config(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            batch_status=BatchStatus.DROPPING,
            batch_size=512,
            queue_depth=1000,
            queue_capacity=2048,
        )
        configs = self.engine.compute_optimal_batch_config()
        assert len(configs) == 1
        assert configs[0]["recommended_batch_size"] > 512

    def test_compute_optimal_batch_config_no_dropping(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            batch_status=BatchStatus.HEALTHY,
            batch_size=512,
            queue_depth=100,
            queue_capacity=2048,
        )
        configs = self.engine.compute_optimal_batch_config()
        assert configs[0]["recommended_batch_size"] == 512

    def test_predict_queue_overflow_critical(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            queue_depth=1900,
            queue_capacity=2048,
        )
        predictions = self.engine.predict_queue_overflow()
        assert len(predictions) == 1
        assert predictions[0]["overflow_risk"] == "critical"

    def test_predict_queue_overflow_high(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            queue_depth=1600,
            queue_capacity=2048,
        )
        predictions = self.engine.predict_queue_overflow()
        assert len(predictions) == 1
        assert predictions[0]["overflow_risk"] == "high"

    def test_predict_queue_overflow_low_risk(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            queue_depth=100,
            queue_capacity=2048,
        )
        predictions = self.engine.predict_queue_overflow()
        assert len(predictions) == 0

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_identify_gaps(self):
        self.engine.add_record(name="low", score=10.0)
        self.engine.add_record(name="high", score=90.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_rank_by_score(self):
        self.engine.add_record(name="a", service="low", score=10.0)
        self.engine.add_record(name="b", service="high", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(name="a", batch_status=BatchStatus.HEALTHY, score=80.0)
        dist = self.engine.analyze_distribution()
        assert "healthy" in dist


# =============================================================================
# OtelExporterReliabilityEngine Tests
# =============================================================================


class TestOtelExporterReliabilityEnums:
    def test_exporter_health_values(self):
        assert ExporterHealth.HEALTHY == "healthy"
        assert ExporterHealth.DEGRADED == "degraded"
        assert ExporterHealth.FAILING == "failing"
        assert ExporterHealth.DEAD == "dead"

    def test_retry_outcome_values(self):
        assert RetryOutcome.SUCCESS == "success"
        assert RetryOutcome.PARTIAL == "partial"
        assert RetryOutcome.EXHAUSTED == "exhausted"

    def test_backend_type_values(self):
        assert BackendType.OTLP_GRPC == "otlp_grpc"
        assert BackendType.OTLP_HTTP == "otlp_http"
        assert BackendType.KAFKA == "kafka"
        assert BackendType.PROMETHEUS_REMOTE_WRITE == "prometheus_remote_write"


class TestOtelExporterReliabilityModels:
    def test_record_defaults(self):
        r = OtelExporterReliabilityRecord()
        assert r.exporter_health == ExporterHealth.HEALTHY
        assert r.total_sent == 0

    def test_analysis_defaults(self):
        a = OtelExporterReliabilityAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = OtelExporterReliabilityReport()
        assert rp.total_records == 0


class TestOtelExporterReliabilityEngine:
    def setup_method(self):
        self.engine = OtelExporterReliabilityEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="exp-1", score=90.0)
        assert r.name == "exp-1"

    def test_get_record(self):
        r = self.engine.add_record(name="exp-1")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_health(self):
        self.engine.add_record(name="a", exporter_health=ExporterHealth.HEALTHY)
        self.engine.add_record(name="b", exporter_health=ExporterHealth.FAILING)
        results = self.engine.list_records(exporter_health=ExporterHealth.FAILING)
        assert len(results) == 1

    def test_list_records_filter_backend(self):
        self.engine.add_record(name="a", backend_type=BackendType.KAFKA)
        self.engine.add_record(name="b", backend_type=BackendType.OTLP_GRPC)
        results = self.engine.list_records(backend_type=BackendType.KAFKA)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_ring_buffer(self):
        engine = OtelExporterReliabilityEngine(max_records=3)
        for i in range(7):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 3

    def test_compute_delivery_rate(self):
        self.engine.add_record(
            name="a", service="svc-a", total_sent=1000, total_failed=50, latency_ms=100.0
        )
        results = self.engine.compute_delivery_rate()
        assert len(results) == 1
        assert results[0]["delivery_rate"] == 0.95

    def test_compute_delivery_rate_zero_sent(self):
        self.engine.add_record(name="a", service="svc-a", total_sent=0, total_failed=0)
        results = self.engine.compute_delivery_rate()
        assert results[0]["delivery_rate"] == 0.0

    def test_identify_failing_exporters(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            exporter_health=ExporterHealth.FAILING,
            retry_outcome=RetryOutcome.EXHAUSTED,
            retry_count=5,
        )
        self.engine.add_record(
            name="b",
            service="svc-b",
            exporter_health=ExporterHealth.HEALTHY,
        )
        results = self.engine.identify_failing_exporters()
        assert len(results) == 1
        assert results[0]["service"] == "svc-a"

    def test_identify_failing_exporters_none(self):
        self.engine.add_record(name="a", service="svc-a", exporter_health=ExporterHealth.HEALTHY)
        assert self.engine.identify_failing_exporters() == []

    def test_recommend_retry_tuning_exhausted(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            retry_outcome=RetryOutcome.EXHAUSTED,
            backend_type=BackendType.OTLP_GRPC,
        )
        results = self.engine.recommend_retry_tuning()
        assert len(results) == 1
        assert results[0]["issue"] == "retries_exhausted"
        assert results[0]["priority"] == "high"

    def test_recommend_retry_tuning_dead(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            exporter_health=ExporterHealth.DEAD,
            retry_outcome=RetryOutcome.SUCCESS,
        )
        results = self.engine.recommend_retry_tuning()
        assert len(results) == 1
        assert results[0]["issue"] == "exporter_dead"
        assert results[0]["priority"] == "critical"

    def test_recommend_retry_tuning_excessive(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            exporter_health=ExporterHealth.DEGRADED,
            retry_outcome=RetryOutcome.PARTIAL,
            retry_count=5,
        )
        results = self.engine.recommend_retry_tuning()
        assert len(results) == 1
        assert results[0]["issue"] == "excessive_retries"

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_process_not_found(self):
        result = self.engine.process("missing")
        assert result["status"] == "not_found"

    def test_identify_gaps(self):
        self.engine.add_record(name="low", score=10.0)
        self.engine.add_record(name="high", score=90.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_healthy(self):
        self.engine.add_record(name="a", score=90.0)
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_teams"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_rank_by_score(self):
        self.engine.add_record(name="a", service="low", score=10.0)
        self.engine.add_record(name="b", service="high", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(name="a", exporter_health=ExporterHealth.HEALTHY, score=80.0)
        dist = self.engine.analyze_distribution()
        assert "healthy" in dist

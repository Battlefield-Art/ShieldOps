"""Tests for OTel engine modules — OTelPipelineHealthEngine,
OTelKafkaIngestionEngine, AutoInstrumentationEngine."""

from __future__ import annotations

from shieldops.observability.auto_instrumentation_engine import (
    AutoInstrumentationAnalysis,
    AutoInstrumentationEngine,
    AutoInstrumentationRecord,
    AutoInstrumentationReport,
    CoverageStatus,
    InstrumentationLanguage,
    InstrumentationMethod,
)
from shieldops.observability.otel_kafka_ingestion_engine import (
    IngestionMetric,
    IngestionStatus,
    KafkaIngestionAnalysis,
    KafkaIngestionRecord,
    KafkaIngestionReport,
    KafkaSignalType,
    OTelKafkaIngestionEngine,
)
from shieldops.observability.otel_pipeline_health_engine import (
    HealthIndicator,
    OTelPipelineHealthEngine,
    PipelineHealthAnalysis,
    PipelineHealthRecord,
    PipelineHealthReport,
    PipelineSignalType,
    PipelineStatus,
)

# ============================================================================
# OTelPipelineHealthEngine
# ============================================================================


def _pipeline_engine(**kw: object) -> OTelPipelineHealthEngine:
    return OTelPipelineHealthEngine(**kw)


class TestPipelineEnums:
    def test_signal_type_traces(self) -> None:
        assert PipelineSignalType.TRACES == "traces"

    def test_signal_type_metrics(self) -> None:
        assert PipelineSignalType.METRICS == "metrics"

    def test_signal_type_logs(self) -> None:
        assert PipelineSignalType.LOGS == "logs"

    def test_signal_type_profiles(self) -> None:
        assert PipelineSignalType.PROFILES == "profiles"

    def test_health_indicator_throughput(self) -> None:
        assert HealthIndicator.THROUGHPUT == "throughput"

    def test_health_indicator_latency(self) -> None:
        assert HealthIndicator.LATENCY == "latency"

    def test_health_indicator_drop_rate(self) -> None:
        assert HealthIndicator.DROP_RATE == "drop_rate"

    def test_health_indicator_queue_depth(self) -> None:
        assert HealthIndicator.QUEUE_DEPTH == "queue_depth"

    def test_pipeline_status_healthy(self) -> None:
        assert PipelineStatus.HEALTHY == "healthy"

    def test_pipeline_status_degraded(self) -> None:
        assert PipelineStatus.DEGRADED == "degraded"

    def test_pipeline_status_backpressure(self) -> None:
        assert PipelineStatus.BACKPRESSURE == "backpressure"

    def test_pipeline_status_failing(self) -> None:
        assert PipelineStatus.FAILING == "failing"


class TestPipelineModels:
    def test_record_defaults(self) -> None:
        r = PipelineHealthRecord()
        assert r.id
        assert r.collector_id == ""
        assert r.signal_type == PipelineSignalType.TRACES
        assert r.health_indicator == HealthIndicator.THROUGHPUT
        assert r.pipeline_status == PipelineStatus.HEALTHY
        assert r.value == 0.0
        assert r.threshold == 0.0
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = PipelineHealthAnalysis()
        assert a.id
        assert a.collector_id == ""
        assert a.avg_value == 0.0
        assert a.max_value == 0.0
        assert a.breach_count == 0
        assert a.pipeline_status == PipelineStatus.HEALTHY
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = PipelineHealthReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_drop_rate == 0.0
        assert r.by_signal_type == {}
        assert r.by_health_indicator == {}
        assert r.by_pipeline_status == {}
        assert r.unhealthy_collectors == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestPipelineAddRecord:
    def test_basic(self) -> None:
        eng = _pipeline_engine()
        r = eng.add_record(
            collector_id="col-1",
            signal_type=PipelineSignalType.METRICS,
            health_indicator=HealthIndicator.LATENCY,
            pipeline_status=PipelineStatus.DEGRADED,
            value=120.5,
            threshold=100.0,
        )
        assert r.collector_id == "col-1"
        assert r.signal_type == PipelineSignalType.METRICS
        assert r.value == 120.5

    def test_eviction_at_max(self) -> None:
        eng = _pipeline_engine(max_records=3)
        for i in range(5):
            eng.add_record(collector_id=f"col-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _pipeline_engine()
        r = eng.add_record(collector_id="col-1")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _pipeline_engine()
        assert eng.get_record("nonexistent") is None


class TestPipelineProcess:
    def test_found(self) -> None:
        eng = _pipeline_engine()
        eng.add_record(collector_id="col-1", value=80.0, threshold=100.0)
        eng.add_record(collector_id="col-1", value=120.0, threshold=100.0)
        analysis = eng.process("col-1")
        assert analysis is not None
        assert analysis.collector_id == "col-1"
        assert analysis.avg_value == 100.0
        assert analysis.max_value == 120.0
        assert analysis.breach_count == 1

    def test_not_found(self) -> None:
        eng = _pipeline_engine()
        assert eng.process("nonexistent") is None

    def test_failing_status(self) -> None:
        eng = _pipeline_engine()
        for _ in range(4):
            eng.add_record(collector_id="col-x", value=200.0, threshold=100.0)
        analysis = eng.process("col-x")
        assert analysis is not None
        assert analysis.pipeline_status == PipelineStatus.FAILING


class TestPipelineReport:
    def test_populated(self) -> None:
        eng = _pipeline_engine(threshold=10.0)
        eng.add_record(
            collector_id="col-1",
            health_indicator=HealthIndicator.DROP_RATE,
            value=50.0,
            pipeline_status=PipelineStatus.FAILING,
        )
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.avg_drop_rate == 50.0
        assert len(report.unhealthy_collectors) == 1
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _pipeline_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.avg_drop_rate == 0.0


class TestPipelineStats:
    def test_empty(self) -> None:
        eng = _pipeline_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _pipeline_engine()
        eng.add_record(collector_id="col-1")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_collectors"] == 1


class TestPipelineClearData:
    def test_clears(self) -> None:
        eng = _pipeline_engine()
        eng.add_record(collector_id="col-1")
        eng.process("col-1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestPipelineDetectBackpressure:
    def test_detects(self) -> None:
        eng = _pipeline_engine()
        eng.add_record(
            collector_id="col-1",
            health_indicator=HealthIndicator.QUEUE_DEPTH,
            value=200.0,
            threshold=100.0,
        )
        eng.add_record(
            collector_id="col-2",
            health_indicator=HealthIndicator.QUEUE_DEPTH,
            value=50.0,
            threshold=100.0,
        )
        results = eng.detect_backpressure()
        assert len(results) == 1
        assert results[0]["collector_id"] == "col-1"

    def test_empty(self) -> None:
        eng = _pipeline_engine()
        assert eng.detect_backpressure() == []


class TestPipelineRankCollectors:
    def test_ranked_worst_first(self) -> None:
        eng = _pipeline_engine()
        eng.add_record(collector_id="good", value=10.0, threshold=100.0)
        eng.add_record(collector_id="bad", value=200.0, threshold=100.0)
        results = eng.rank_collectors_by_health()
        assert results[0]["collector_id"] == "bad"
        assert results[0]["health_score"] < results[1]["health_score"]

    def test_empty(self) -> None:
        eng = _pipeline_engine()
        assert eng.rank_collectors_by_health() == []


class TestPipelineRecommendScaling:
    def test_scale_up(self) -> None:
        eng = _pipeline_engine(threshold=10.0)
        eng.add_record(
            collector_id="col-1",
            health_indicator=HealthIndicator.DROP_RATE,
            value=50.0,
        )
        results = eng.recommend_scaling()
        assert len(results) == 1
        assert results[0]["recommendation"] == "scale_up"

    def test_no_change(self) -> None:
        eng = _pipeline_engine(threshold=100.0)
        eng.add_record(
            collector_id="col-1",
            health_indicator=HealthIndicator.DROP_RATE,
            value=30.0,
        )
        eng.add_record(
            collector_id="col-1",
            health_indicator=HealthIndicator.QUEUE_DEPTH,
            value=30.0,
        )
        results = eng.recommend_scaling()
        assert len(results) == 1
        assert results[0]["recommendation"] == "no_change"


# ============================================================================
# OTelKafkaIngestionEngine
# ============================================================================


def _kafka_engine(**kw: object) -> OTelKafkaIngestionEngine:
    return OTelKafkaIngestionEngine(**kw)


class TestKafkaEnums:
    def test_signal_type_otlp_proto(self) -> None:
        assert KafkaSignalType.OTLP_PROTO == "otlp_proto"

    def test_signal_type_otlp_json(self) -> None:
        assert KafkaSignalType.OTLP_JSON == "otlp_json"

    def test_signal_type_raw_json(self) -> None:
        assert KafkaSignalType.RAW_JSON == "raw_json"

    def test_signal_type_avro(self) -> None:
        assert KafkaSignalType.AVRO == "avro"

    def test_ingestion_metric_throughput(self) -> None:
        assert IngestionMetric.THROUGHPUT == "throughput"

    def test_ingestion_metric_consumer_lag(self) -> None:
        assert IngestionMetric.CONSUMER_LAG == "consumer_lag"

    def test_ingestion_metric_encoding_error(self) -> None:
        assert IngestionMetric.ENCODING_ERROR == "encoding_error"

    def test_ingestion_metric_partition_skew(self) -> None:
        assert IngestionMetric.PARTITION_SKEW == "partition_skew"

    def test_ingestion_status_nominal(self) -> None:
        assert IngestionStatus.NOMINAL == "nominal"

    def test_ingestion_status_lagging(self) -> None:
        assert IngestionStatus.LAGGING == "lagging"

    def test_ingestion_status_erroring(self) -> None:
        assert IngestionStatus.ERRORING == "erroring"

    def test_ingestion_status_stalled(self) -> None:
        assert IngestionStatus.STALLED == "stalled"


class TestKafkaModels:
    def test_record_defaults(self) -> None:
        r = KafkaIngestionRecord()
        assert r.id
        assert r.topic == ""
        assert r.signal_type == KafkaSignalType.OTLP_PROTO
        assert r.ingestion_metric == IngestionMetric.THROUGHPUT
        assert r.ingestion_status == IngestionStatus.NOMINAL
        assert r.value == 0.0
        assert r.partition_id == 0
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = KafkaIngestionAnalysis()
        assert a.id
        assert a.topic == ""
        assert a.avg_throughput == 0.0
        assert a.max_lag == 0.0
        assert a.error_count == 0
        assert a.ingestion_status == IngestionStatus.NOMINAL
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = KafkaIngestionReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_throughput == 0.0
        assert r.by_signal_type == {}
        assert r.by_ingestion_metric == {}
        assert r.by_ingestion_status == {}
        assert r.lagging_topics == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestKafkaAddRecord:
    def test_basic(self) -> None:
        eng = _kafka_engine()
        r = eng.add_record(
            topic="otel-traces",
            signal_type=KafkaSignalType.OTLP_PROTO,
            ingestion_metric=IngestionMetric.THROUGHPUT,
            value=1000.0,
            partition_id=3,
        )
        assert r.topic == "otel-traces"
        assert r.value == 1000.0
        assert r.partition_id == 3

    def test_eviction_at_max(self) -> None:
        eng = _kafka_engine(max_records=3)
        for i in range(5):
            eng.add_record(topic=f"topic-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _kafka_engine()
        r = eng.add_record(topic="t1")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _kafka_engine()
        assert eng.get_record("nonexistent") is None


class TestKafkaProcess:
    def test_found(self) -> None:
        eng = _kafka_engine()
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.THROUGHPUT,
            value=500.0,
        )
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.CONSUMER_LAG,
            value=20.0,
        )
        analysis = eng.process("t1")
        assert analysis is not None
        assert analysis.topic == "t1"
        assert analysis.avg_throughput == 500.0
        assert analysis.max_lag == 20.0

    def test_not_found(self) -> None:
        eng = _kafka_engine()
        assert eng.process("nonexistent") is None

    def test_erroring_status(self) -> None:
        eng = _kafka_engine()
        for _ in range(5):
            eng.add_record(
                topic="t1",
                ingestion_metric=IngestionMetric.ENCODING_ERROR,
                value=1.0,
            )
        analysis = eng.process("t1")
        assert analysis is not None
        assert analysis.ingestion_status == IngestionStatus.ERRORING


class TestKafkaReport:
    def test_populated(self) -> None:
        eng = _kafka_engine(threshold=100.0)
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.THROUGHPUT,
            ingestion_status=IngestionStatus.LAGGING,
            value=50.0,
        )
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.avg_throughput == 50.0
        assert len(report.lagging_topics) == 1
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _kafka_engine()
        report = eng.generate_report()
        assert report.total_records == 0


class TestKafkaStats:
    def test_empty(self) -> None:
        eng = _kafka_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _kafka_engine()
        eng.add_record(topic="t1")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_topics"] == 1


class TestKafkaClearData:
    def test_clears(self) -> None:
        eng = _kafka_engine()
        eng.add_record(topic="t1")
        eng.process("t1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestKafkaDetectConsumerLag:
    def test_detects_high_lag(self) -> None:
        eng = _kafka_engine(threshold=50.0)
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.CONSUMER_LAG,
            value=100.0,
        )
        eng.add_record(
            topic="t2",
            ingestion_metric=IngestionMetric.CONSUMER_LAG,
            value=10.0,
        )
        results = eng.detect_consumer_lag()
        assert len(results) == 1
        assert results[0]["topic"] == "t1"

    def test_empty(self) -> None:
        eng = _kafka_engine()
        assert eng.detect_consumer_lag() == []


class TestKafkaPartitionDistribution:
    def test_detects_skew(self) -> None:
        eng = _kafka_engine()
        for _ in range(10):
            eng.add_record(topic="t1", partition_id=0)
        eng.add_record(topic="t1", partition_id=1)
        results = eng.analyze_partition_distribution()
        assert len(results) == 1
        assert results[0]["skewed"] is True

    def test_balanced(self) -> None:
        eng = _kafka_engine()
        eng.add_record(topic="t1", partition_id=0)
        eng.add_record(topic="t1", partition_id=1)
        results = eng.analyze_partition_distribution()
        assert len(results) == 1
        assert results[0]["skewed"] is False


class TestKafkaEstimateCapacity:
    def test_at_capacity(self) -> None:
        eng = _kafka_engine()
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.THROUGHPUT,
            value=95.0,
        )
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.THROUGHPUT,
            value=100.0,
        )
        results = eng.estimate_ingestion_capacity()
        assert len(results) == 1
        assert results[0]["headroom_pct"] < 10.0
        assert results[0]["at_capacity"] is True

    def test_has_headroom(self) -> None:
        eng = _kafka_engine()
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.THROUGHPUT,
            value=50.0,
        )
        eng.add_record(
            topic="t1",
            ingestion_metric=IngestionMetric.THROUGHPUT,
            value=100.0,
        )
        results = eng.estimate_ingestion_capacity()
        assert results[0]["at_capacity"] is False


# ============================================================================
# AutoInstrumentationEngine
# ============================================================================


def _auto_engine(**kw: object) -> AutoInstrumentationEngine:
    return AutoInstrumentationEngine(**kw)


class TestAutoEnums:
    def test_language_python(self) -> None:
        assert InstrumentationLanguage.PYTHON == "python"

    def test_language_java(self) -> None:
        assert InstrumentationLanguage.JAVA == "java"

    def test_language_nodejs(self) -> None:
        assert InstrumentationLanguage.NODEJS == "nodejs"

    def test_language_go(self) -> None:
        assert InstrumentationLanguage.GO == "go"

    def test_language_dotnet(self) -> None:
        assert InstrumentationLanguage.DOTNET == "dotnet"

    def test_method_runtime_patch(self) -> None:
        assert InstrumentationMethod.RUNTIME_PATCH == "runtime_patch"

    def test_method_sdk_manual(self) -> None:
        assert InstrumentationMethod.SDK_MANUAL == "sdk_manual"

    def test_method_ebpf(self) -> None:
        assert InstrumentationMethod.EBPF == "ebpf"

    def test_method_operator_injection(self) -> None:
        assert InstrumentationMethod.OPERATOR_INJECTION == "operator_injection"

    def test_coverage_full(self) -> None:
        assert CoverageStatus.FULL == "full"

    def test_coverage_partial(self) -> None:
        assert CoverageStatus.PARTIAL == "partial"

    def test_coverage_none(self) -> None:
        assert CoverageStatus.NONE == "none"

    def test_coverage_incompatible(self) -> None:
        assert CoverageStatus.INCOMPATIBLE == "incompatible"


class TestAutoModels:
    def test_record_defaults(self) -> None:
        r = AutoInstrumentationRecord()
        assert r.id
        assert r.service_name == ""
        assert r.language == InstrumentationLanguage.PYTHON
        assert r.method == InstrumentationMethod.RUNTIME_PATCH
        assert r.coverage_status == CoverageStatus.NONE
        assert r.libraries_instrumented == 0
        assert r.libraries_total == 0
        assert r.trace_coverage_pct == 0.0
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = AutoInstrumentationAnalysis()
        assert a.id
        assert a.service_name == ""
        assert a.coverage_pct == 0.0
        assert a.gap_count == 0
        assert a.method == InstrumentationMethod.RUNTIME_PATCH
        assert a.coverage_status == CoverageStatus.NONE
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = AutoInstrumentationReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_coverage_pct == 0.0
        assert r.by_language == {}
        assert r.by_method == {}
        assert r.by_coverage_status == {}
        assert r.uninstrumented_services == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestAutoAddRecord:
    def test_basic(self) -> None:
        eng = _auto_engine()
        r = eng.add_record(
            service_name="auth-svc",
            language=InstrumentationLanguage.JAVA,
            method=InstrumentationMethod.OPERATOR_INJECTION,
            coverage_status=CoverageStatus.FULL,
            libraries_instrumented=15,
            libraries_total=15,
            trace_coverage_pct=100.0,
        )
        assert r.service_name == "auth-svc"
        assert r.language == InstrumentationLanguage.JAVA
        assert r.trace_coverage_pct == 100.0

    def test_eviction_at_max(self) -> None:
        eng = _auto_engine(max_records=3)
        for i in range(5):
            eng.add_record(service_name=f"svc-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _auto_engine()
        r = eng.add_record(service_name="svc-a")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _auto_engine()
        assert eng.get_record("nonexistent") is None


class TestAutoProcess:
    def test_found(self) -> None:
        eng = _auto_engine()
        eng.add_record(
            service_name="svc-a",
            trace_coverage_pct=80.0,
            coverage_status=CoverageStatus.PARTIAL,
        )
        eng.add_record(
            service_name="svc-a",
            trace_coverage_pct=60.0,
            coverage_status=CoverageStatus.PARTIAL,
        )
        analysis = eng.process("svc-a")
        assert analysis is not None
        assert analysis.service_name == "svc-a"
        assert analysis.coverage_pct == 70.0
        assert analysis.gap_count == 2
        assert analysis.coverage_status == CoverageStatus.PARTIAL

    def test_not_found(self) -> None:
        eng = _auto_engine()
        assert eng.process("nonexistent") is None

    def test_full_coverage_status(self) -> None:
        eng = _auto_engine()
        eng.add_record(
            service_name="svc-x",
            trace_coverage_pct=95.0,
            coverage_status=CoverageStatus.FULL,
        )
        analysis = eng.process("svc-x")
        assert analysis is not None
        assert analysis.coverage_status == CoverageStatus.FULL


class TestAutoReport:
    def test_populated(self) -> None:
        eng = _auto_engine(threshold=80.0)
        eng.add_record(
            service_name="svc-a",
            coverage_status=CoverageStatus.NONE,
            trace_coverage_pct=10.0,
        )
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.avg_coverage_pct == 10.0
        assert len(report.uninstrumented_services) == 1
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _auto_engine()
        report = eng.generate_report()
        assert report.total_records == 0


class TestAutoStats:
    def test_empty(self) -> None:
        eng = _auto_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _auto_engine()
        eng.add_record(service_name="svc-a")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1


class TestAutoClearData:
    def test_clears(self) -> None:
        eng = _auto_engine()
        eng.add_record(service_name="svc-a")
        eng.process("svc-a")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestAutoIdentifyCoverageGaps:
    def test_detects_gaps(self) -> None:
        eng = _auto_engine()
        eng.add_record(
            service_name="svc-a",
            coverage_status=CoverageStatus.NONE,
            trace_coverage_pct=0.0,
        )
        eng.add_record(
            service_name="svc-b",
            coverage_status=CoverageStatus.FULL,
            trace_coverage_pct=100.0,
        )
        results = eng.identify_coverage_gaps()
        assert len(results) == 1
        assert results[0]["service_name"] == "svc-a"

    def test_empty(self) -> None:
        eng = _auto_engine()
        assert eng.identify_coverage_gaps() == []


class TestAutoRecommendMethod:
    def test_recommends_best(self) -> None:
        eng = _auto_engine()
        eng.add_record(
            service_name="svc-a",
            language=InstrumentationLanguage.PYTHON,
            method=InstrumentationMethod.RUNTIME_PATCH,
            trace_coverage_pct=90.0,
        )
        eng.add_record(
            service_name="svc-b",
            language=InstrumentationLanguage.PYTHON,
            method=InstrumentationMethod.SDK_MANUAL,
            trace_coverage_pct=60.0,
        )
        results = eng.recommend_instrumentation_method()
        assert len(results) == 1
        assert results[0]["language"] == "python"
        assert results[0]["recommended_method"] == "runtime_patch"

    def test_multiple_languages(self) -> None:
        eng = _auto_engine()
        eng.add_record(
            service_name="svc-a",
            language=InstrumentationLanguage.PYTHON,
            method=InstrumentationMethod.RUNTIME_PATCH,
            trace_coverage_pct=80.0,
        )
        eng.add_record(
            service_name="svc-b",
            language=InstrumentationLanguage.GO,
            method=InstrumentationMethod.EBPF,
            trace_coverage_pct=70.0,
        )
        results = eng.recommend_instrumentation_method()
        assert len(results) == 2


class TestAutoCalculateOverallCoverage:
    def test_with_data(self) -> None:
        eng = _auto_engine()
        eng.add_record(
            service_name="svc-a",
            trace_coverage_pct=100.0,
            coverage_status=CoverageStatus.FULL,
        )
        eng.add_record(
            service_name="svc-b",
            trace_coverage_pct=0.0,
            coverage_status=CoverageStatus.NONE,
        )
        result = eng.calculate_overall_coverage()
        assert result["overall_coverage_pct"] == 50.0
        assert result["total_services"] == 2
        assert result["fully_covered"] == 1
        assert result["not_covered"] == 1

    def test_empty(self) -> None:
        eng = _auto_engine()
        result = eng.calculate_overall_coverage()
        assert result["overall_coverage_pct"] == 0.0
        assert result["total_services"] == 0

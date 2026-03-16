"""Tests for advanced OTel engine modules — OTelCollectorAutoscalerEngine,
OTelTraceSamplingOptimizerEngine, OTelResourceAttributionEngine,
TelemetryCostOptimizerEngine."""

from __future__ import annotations

from shieldops.observability.otel_collector_autoscaler_engine import (
    CollectorAutoscalerAnalysis,
    CollectorAutoscalerRecord,
    CollectorAutoscalerReport,
    OTelCollectorAutoscalerEngine,
    ScaleDirection,
    ScalerStatus,
    ScalingMetric,
)
from shieldops.observability.otel_resource_attribution_engine import (
    AttributionMethod,
    CostTrend,
    OTelResourceAttributionEngine,
    ResourceAttributionAnalysis,
    ResourceAttributionRecord,
    ResourceAttributionReport,
    ResourceCostType,
)
from shieldops.observability.otel_trace_sampling_optimizer_engine import (
    OTelTraceSamplingOptimizerEngine,
    SamplingOptimization,
    SamplingStrategy,
    TraceImportance,
    TraceSamplingAnalysis,
    TraceSamplingRecord,
    TraceSamplingReport,
)
from shieldops.observability.telemetry_cost_optimizer_engine import (
    CostCategory,
    OptimizationStrategy,
    SavingsStatus,
    TelemetryCostAnalysis,
    TelemetryCostOptimizerEngine,
    TelemetryCostRecord,
    TelemetryCostReport,
)

# ============================================================================
# OTelCollectorAutoscalerEngine
# ============================================================================


def _autoscaler_engine(**kw: object) -> OTelCollectorAutoscalerEngine:
    return OTelCollectorAutoscalerEngine(**kw)


class TestAutoscalerEnums:
    def test_scale_direction_values(self) -> None:
        assert ScaleDirection.SCALE_UP == "scale_up"
        assert ScaleDirection.SCALE_DOWN == "scale_down"
        assert ScaleDirection.MAINTAIN == "maintain"
        assert ScaleDirection.EMERGENCY_SCALE == "emergency_scale"

    def test_scaling_metric_values(self) -> None:
        assert ScalingMetric.TELEMETRY_VOLUME == "telemetry_volume"
        assert ScalingMetric.QUEUE_DEPTH == "queue_depth"
        assert ScalingMetric.CPU_UTILIZATION == "cpu_utilization"
        assert ScalingMetric.MEMORY_UTILIZATION == "memory_utilization"

    def test_scaler_status_values(self) -> None:
        assert ScalerStatus.IDLE == "idle"
        assert ScalerStatus.SCALING == "scaling"
        assert ScalerStatus.COOLDOWN == "cooldown"
        assert ScalerStatus.ERROR == "error"


class TestAutoscalerModels:
    def test_record_defaults(self) -> None:
        r = CollectorAutoscalerRecord()
        assert r.id
        assert r.collector_id == ""
        assert r.scale_direction == ScaleDirection.MAINTAIN
        assert r.scaling_metric == ScalingMetric.TELEMETRY_VOLUME
        assert r.scaler_status == ScalerStatus.IDLE
        assert r.value == 0.0
        assert r.threshold == 0.0
        assert r.replica_count == 1
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = CollectorAutoscalerAnalysis()
        assert a.id
        assert a.collector_id == ""
        assert a.avg_value == 0.0
        assert a.max_value == 0.0
        assert a.breach_count == 0
        assert a.recommended_direction == ScaleDirection.MAINTAIN
        assert a.recommended_replicas == 1

    def test_report_defaults(self) -> None:
        r = CollectorAutoscalerReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_utilization == 0.0
        assert r.by_scale_direction == {}
        assert r.by_scaling_metric == {}
        assert r.by_scaler_status == {}
        assert r.collectors_needing_scale == []
        assert r.recommendations == []


class TestAutoscalerAddRecord:
    def test_basic(self) -> None:
        eng = _autoscaler_engine()
        r = eng.add_record(
            collector_id="col-1",
            scaling_metric=ScalingMetric.CPU_UTILIZATION,
            value=85.0,
            threshold=80.0,
        )
        assert r.collector_id == "col-1"
        assert r.scaling_metric == ScalingMetric.CPU_UTILIZATION
        assert r.value == 85.0

    def test_eviction_at_max(self) -> None:
        eng = _autoscaler_engine(max_records=3)
        for i in range(5):
            eng.add_record(collector_id=f"col-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _autoscaler_engine()
        r = eng.add_record(collector_id="col-1")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _autoscaler_engine()
        assert eng.get_record("nonexistent") is None

    def test_list_records_filter_by_collector(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1")
        eng.add_record(collector_id="col-2")
        results = eng.list_records(collector_id="col-1")
        assert len(results) == 1
        assert results[0].collector_id == "col-1"


class TestAutoscalerProcess:
    def test_found(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1", value=80.0, threshold=100.0)
        eng.add_record(collector_id="col-1", value=120.0, threshold=100.0)
        analysis = eng.process("col-1")
        assert analysis is not None
        assert analysis.collector_id == "col-1"
        assert analysis.avg_value == 100.0
        assert analysis.max_value == 120.0

    def test_not_found(self) -> None:
        eng = _autoscaler_engine()
        assert eng.process("nonexistent") is None

    def test_emergency_scale(self) -> None:
        eng = _autoscaler_engine()
        for _ in range(4):
            eng.add_record(collector_id="col-x", value=200.0, threshold=100.0)
        analysis = eng.process("col-x")
        assert analysis is not None
        assert analysis.recommended_direction == ScaleDirection.EMERGENCY_SCALE


class TestAutoscalerReport:
    def test_populated(self) -> None:
        eng = _autoscaler_engine(threshold=50.0)
        eng.add_record(collector_id="col-1", value=90.0, threshold=80.0)
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.avg_utilization == 90.0
        assert len(report.collectors_needing_scale) == 1
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _autoscaler_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.avg_utilization == 0.0


class TestAutoscalerStats:
    def test_empty(self) -> None:
        eng = _autoscaler_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_collectors"] == 1


class TestAutoscalerClearData:
    def test_clears(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1")
        eng.process("col-1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestAutoscalerComputeScaling:
    def test_no_data(self) -> None:
        eng = _autoscaler_engine()
        result = eng.compute_scaling_recommendation("col-1")
        assert result["status"] == "no_data"

    def test_with_data(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1", value=50.0, threshold=100.0)
        result = eng.compute_scaling_recommendation("col-1")
        assert result["collector_id"] == "col-1"
        assert "direction" in result
        assert result["record_count"] == 1


class TestAutoscalerDetectSpikes:
    def test_detects_spike(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1", value=10.0)
        eng.add_record(collector_id="col-1", value=10.0)
        eng.add_record(collector_id="col-1", value=100.0)
        eng.add_record(collector_id="col-1", value=100.0)
        results = eng.detect_traffic_spikes()
        assert len(results) >= 1
        assert results[0]["collector_id"] == "col-1"
        assert results[0]["spike_ratio"] > 2.0

    def test_no_spike(self) -> None:
        eng = _autoscaler_engine()
        eng.add_record(collector_id="col-1", value=10.0)
        eng.add_record(collector_id="col-1", value=10.0)
        eng.add_record(collector_id="col-1", value=10.0)
        results = eng.detect_traffic_spikes()
        assert len(results) == 0

    def test_empty(self) -> None:
        eng = _autoscaler_engine()
        assert eng.detect_traffic_spikes() == []


class TestAutoscalerOptimizeReplicas:
    def test_with_data(self) -> None:
        eng = _autoscaler_engine(threshold=50.0)
        eng.add_record(collector_id="col-1", value=100.0, replica_count=1)
        results = eng.optimize_replica_count()
        assert len(results) == 1
        assert results[0]["collector_id"] == "col-1"
        assert results[0]["optimal_replicas"] == 2

    def test_empty(self) -> None:
        eng = _autoscaler_engine()
        assert eng.optimize_replica_count() == []


# ============================================================================
# OTelTraceSamplingOptimizerEngine
# ============================================================================


def _sampling_engine(**kw: object) -> OTelTraceSamplingOptimizerEngine:
    return OTelTraceSamplingOptimizerEngine(**kw)


class TestSamplingEnums:
    def test_strategy_values(self) -> None:
        assert SamplingStrategy.FULL_FIDELITY == "full_fidelity"
        assert SamplingStrategy.HEAD_BASED == "head_based"
        assert SamplingStrategy.TAIL_BASED == "tail_based"
        assert SamplingStrategy.ADAPTIVE == "adaptive"
        assert SamplingStrategy.PRIORITY_BASED == "priority_based"

    def test_importance_values(self) -> None:
        assert TraceImportance.CRITICAL == "critical"
        assert TraceImportance.HIGH == "high"
        assert TraceImportance.NORMAL == "normal"
        assert TraceImportance.LOW == "low"
        assert TraceImportance.NOISE == "noise"

    def test_optimization_values(self) -> None:
        assert SamplingOptimization.COST_OPTIMIZED == "cost_optimized"
        assert SamplingOptimization.FIDELITY_OPTIMIZED == "fidelity_optimized"
        assert SamplingOptimization.BALANCED == "balanced"
        assert SamplingOptimization.INCIDENT_FOCUSED == "incident_focused"


class TestSamplingModels:
    def test_record_defaults(self) -> None:
        r = TraceSamplingRecord()
        assert r.id
        assert r.service_name == ""
        assert r.sampling_strategy == SamplingStrategy.HEAD_BASED
        assert r.trace_importance == TraceImportance.NORMAL
        assert r.sampling_optimization == SamplingOptimization.BALANCED
        assert r.current_rate == 1.0
        assert r.traces_per_second == 0.0
        assert r.cost_per_day_usd == 0.0
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = TraceSamplingAnalysis()
        assert a.id
        assert a.service_name == ""
        assert a.avg_rate == 0.0
        assert a.recommended_rate == 1.0
        assert a.projected_savings_usd == 0.0

    def test_report_defaults(self) -> None:
        r = TraceSamplingReport()
        assert r.id
        assert r.total_records == 0
        assert r.avg_sampling_rate == 0.0
        assert r.total_cost_per_day_usd == 0.0
        assert r.by_sampling_strategy == {}
        assert r.over_sampled_services == []
        assert r.recommendations == []


class TestSamplingAddRecord:
    def test_basic(self) -> None:
        eng = _sampling_engine()
        r = eng.add_record(
            service_name="svc-a",
            sampling_strategy=SamplingStrategy.TAIL_BASED,
            trace_importance=TraceImportance.HIGH,
            current_rate=0.5,
            cost_per_day_usd=100.0,
        )
        assert r.service_name == "svc-a"
        assert r.sampling_strategy == SamplingStrategy.TAIL_BASED
        assert r.current_rate == 0.5

    def test_eviction_at_max(self) -> None:
        eng = _sampling_engine(max_records=3)
        for i in range(5):
            eng.add_record(service_name=f"svc-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _sampling_engine()
        r = eng.add_record(service_name="svc-a")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _sampling_engine()
        assert eng.get_record("nonexistent") is None

    def test_list_records_filter(self) -> None:
        eng = _sampling_engine()
        eng.add_record(service_name="svc-a")
        eng.add_record(service_name="svc-b")
        results = eng.list_records(service_name="svc-a")
        assert len(results) == 1


class TestSamplingProcess:
    def test_found(self) -> None:
        eng = _sampling_engine(threshold=0.5)
        eng.add_record(
            service_name="svc-a",
            current_rate=0.8,
            trace_importance=TraceImportance.LOW,
            cost_per_day_usd=50.0,
        )
        analysis = eng.process("svc-a")
        assert analysis is not None
        assert analysis.service_name == "svc-a"
        assert analysis.avg_rate == 0.8
        assert analysis.recommended_rate < 0.8

    def test_not_found(self) -> None:
        eng = _sampling_engine()
        assert eng.process("nonexistent") is None

    def test_critical_keeps_high_rate(self) -> None:
        eng = _sampling_engine()
        eng.add_record(
            service_name="svc-crit",
            current_rate=0.5,
            trace_importance=TraceImportance.CRITICAL,
        )
        analysis = eng.process("svc-crit")
        assert analysis is not None
        assert analysis.recommended_rate >= 0.5


class TestSamplingReport:
    def test_populated(self) -> None:
        eng = _sampling_engine(threshold=0.3)
        eng.add_record(service_name="svc-a", current_rate=0.8, cost_per_day_usd=100.0)
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.total_cost_per_day_usd == 100.0
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _sampling_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.avg_sampling_rate == 0.0


class TestSamplingStats:
    def test_empty(self) -> None:
        eng = _sampling_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _sampling_engine()
        eng.add_record(service_name="svc-a")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1


class TestSamplingClearData:
    def test_clears(self) -> None:
        eng = _sampling_engine()
        eng.add_record(service_name="svc-a")
        eng.process("svc-a")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestSamplingRecommendRate:
    def test_no_data(self) -> None:
        eng = _sampling_engine()
        result = eng.recommend_sampling_rate("svc-a")
        assert result["status"] == "no_data"

    def test_with_data(self) -> None:
        eng = _sampling_engine()
        eng.add_record(service_name="svc-a", current_rate=0.8, traces_per_second=500.0)
        result = eng.recommend_sampling_rate("svc-a")
        assert result["service_name"] == "svc-a"
        assert "recommended_rate" in result


class TestSamplingEstimateSavings:
    def test_no_data(self) -> None:
        eng = _sampling_engine()
        result = eng.estimate_cost_savings(0.1)
        assert result["status"] == "no_data"

    def test_with_data(self) -> None:
        eng = _sampling_engine()
        eng.add_record(service_name="svc-a", current_rate=1.0, cost_per_day_usd=100.0)
        result = eng.estimate_cost_savings(0.5)
        assert result["projected_daily_savings_usd"] == 50.0
        assert result["projected_monthly_savings_usd"] == 1500.0


class TestSamplingOverSampled:
    def test_finds_over_sampled(self) -> None:
        eng = _sampling_engine(threshold=0.3)
        eng.add_record(
            service_name="svc-a",
            current_rate=0.8,
            trace_importance=TraceImportance.LOW,
            cost_per_day_usd=100.0,
        )
        results = eng.identify_over_sampled_services()
        assert len(results) == 1
        assert results[0]["service_name"] == "svc-a"

    def test_critical_not_flagged(self) -> None:
        eng = _sampling_engine(threshold=0.3)
        eng.add_record(
            service_name="svc-crit",
            current_rate=1.0,
            trace_importance=TraceImportance.CRITICAL,
        )
        results = eng.identify_over_sampled_services()
        assert len(results) == 0


# ============================================================================
# OTelResourceAttributionEngine
# ============================================================================


def _attribution_engine(**kw: object) -> OTelResourceAttributionEngine:
    return OTelResourceAttributionEngine(**kw)


class TestAttributionEnums:
    def test_cost_type_values(self) -> None:
        assert ResourceCostType.STORAGE == "storage"
        assert ResourceCostType.PROCESSING == "processing"
        assert ResourceCostType.EXPORT == "export"
        assert ResourceCostType.INGESTION == "ingestion"

    def test_attribution_method_values(self) -> None:
        assert AttributionMethod.PROPORTIONAL == "proportional"
        assert AttributionMethod.FIXED_ALLOCATION == "fixed_allocation"
        assert AttributionMethod.USAGE_BASED == "usage_based"
        assert AttributionMethod.TIERED == "tiered"

    def test_cost_trend_values(self) -> None:
        assert CostTrend.INCREASING == "increasing"
        assert CostTrend.STABLE == "stable"
        assert CostTrend.DECREASING == "decreasing"
        assert CostTrend.ANOMALOUS == "anomalous"


class TestAttributionModels:
    def test_record_defaults(self) -> None:
        r = ResourceAttributionRecord()
        assert r.id
        assert r.service_name == ""
        assert r.resource_cost_type == ResourceCostType.STORAGE
        assert r.attribution_method == AttributionMethod.USAGE_BASED
        assert r.cost_trend == CostTrend.STABLE
        assert r.cost_usd == 0.0
        assert r.volume_bytes == 0.0

    def test_analysis_defaults(self) -> None:
        a = ResourceAttributionAnalysis()
        assert a.id
        assert a.service_name == ""
        assert a.total_cost_usd == 0.0
        assert a.avg_cost_usd == 0.0
        assert a.is_outlier is False

    def test_report_defaults(self) -> None:
        r = ResourceAttributionReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_cost_usd == 0.0
        assert r.by_resource_cost_type == {}
        assert r.cost_outlier_services == []
        assert r.recommendations == []


class TestAttributionAddRecord:
    def test_basic(self) -> None:
        eng = _attribution_engine()
        r = eng.add_record(
            service_name="svc-a",
            resource_cost_type=ResourceCostType.PROCESSING,
            cost_usd=250.0,
            volume_bytes=1_000_000.0,
        )
        assert r.service_name == "svc-a"
        assert r.resource_cost_type == ResourceCostType.PROCESSING
        assert r.cost_usd == 250.0

    def test_eviction_at_max(self) -> None:
        eng = _attribution_engine(max_records=3)
        for i in range(5):
            eng.add_record(service_name=f"svc-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _attribution_engine()
        r = eng.add_record(service_name="svc-a")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _attribution_engine()
        assert eng.get_record("nonexistent") is None


class TestAttributionProcess:
    def test_found(self) -> None:
        eng = _attribution_engine(threshold=100.0)
        eng.add_record(service_name="svc-a", cost_usd=200.0)
        eng.add_record(service_name="svc-a", cost_usd=300.0)
        analysis = eng.process("svc-a")
        assert analysis is not None
        assert analysis.service_name == "svc-a"
        assert analysis.total_cost_usd == 500.0
        assert analysis.avg_cost_usd == 250.0
        assert analysis.is_outlier is True

    def test_not_found(self) -> None:
        eng = _attribution_engine()
        assert eng.process("nonexistent") is None

    def test_trend_detection(self) -> None:
        eng = _attribution_engine()
        for _ in range(3):
            eng.add_record(service_name="svc-t", cost_usd=10.0)
        for _ in range(3):
            eng.add_record(service_name="svc-t", cost_usd=100.0)
        analysis = eng.process("svc-t")
        assert analysis is not None
        assert analysis.cost_trend in (CostTrend.INCREASING, CostTrend.ANOMALOUS)


class TestAttributionReport:
    def test_populated(self) -> None:
        eng = _attribution_engine(threshold=50.0)
        eng.add_record(service_name="svc-a", cost_usd=200.0)
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.total_cost_usd == 200.0
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _attribution_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.total_cost_usd == 0.0


class TestAttributionStats:
    def test_empty(self) -> None:
        eng = _attribution_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _attribution_engine()
        eng.add_record(service_name="svc-a")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1


class TestAttributionClearData:
    def test_clears(self) -> None:
        eng = _attribution_engine()
        eng.add_record(service_name="svc-a")
        eng.process("svc-a")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestAttributionComputeServiceCost:
    def test_no_data(self) -> None:
        eng = _attribution_engine()
        result = eng.compute_service_cost("svc-a")
        assert result["status"] == "no_data"

    def test_with_data(self) -> None:
        eng = _attribution_engine(threshold=100.0)
        eng.add_record(
            service_name="svc-a",
            resource_cost_type=ResourceCostType.STORAGE,
            cost_usd=50.0,
            volume_bytes=500.0,
        )
        eng.add_record(
            service_name="svc-a",
            resource_cost_type=ResourceCostType.PROCESSING,
            cost_usd=75.0,
            volume_bytes=300.0,
        )
        result = eng.compute_service_cost("svc-a")
        assert result["total_cost_usd"] == 125.0
        assert result["cost_by_type"]["storage"] == 50.0
        assert result["cost_by_type"]["processing"] == 75.0
        assert result["total_volume_bytes"] == 800.0


class TestAttributionCostOutliers:
    def test_finds_outliers(self) -> None:
        eng = _attribution_engine(threshold=100.0)
        eng.add_record(service_name="cheap", cost_usd=10.0)
        eng.add_record(service_name="expensive", cost_usd=500.0)
        results = eng.identify_cost_outliers()
        assert len(results) >= 1
        assert results[0]["service_name"] == "expensive"

    def test_empty(self) -> None:
        eng = _attribution_engine()
        assert eng.identify_cost_outliers() == []


class TestAttributionChargeback:
    def test_generates_chargeback(self) -> None:
        eng = _attribution_engine()
        eng.add_record(service_name="svc-a", cost_usd=100.0, team="team-a")
        eng.add_record(service_name="svc-b", cost_usd=300.0, team="team-b")
        results = eng.generate_chargeback_report()
        assert len(results) == 2
        assert results[0]["team"] == "team-b"
        assert results[0]["cost_share_pct"] == 75.0

    def test_empty(self) -> None:
        eng = _attribution_engine()
        assert eng.generate_chargeback_report() == []


# ============================================================================
# TelemetryCostOptimizerEngine
# ============================================================================


def _cost_optimizer_engine(**kw: object) -> TelemetryCostOptimizerEngine:
    return TelemetryCostOptimizerEngine(**kw)


class TestCostOptimizerEnums:
    def test_category_values(self) -> None:
        assert CostCategory.COLLECTION == "collection"
        assert CostCategory.PROCESSING == "processing"
        assert CostCategory.STORAGE == "storage"
        assert CostCategory.EXPORT == "export"

    def test_strategy_values(self) -> None:
        assert OptimizationStrategy.DROP_LOW_VALUE == "drop_low_value"
        assert OptimizationStrategy.AGGREGATE == "aggregate"
        assert OptimizationStrategy.DOWNSAMPLE == "downsample"
        assert OptimizationStrategy.COMPRESS == "compress"

    def test_status_values(self) -> None:
        assert SavingsStatus.PROJECTED == "projected"
        assert SavingsStatus.REALIZED == "realized"
        assert SavingsStatus.MISSED == "missed"
        assert SavingsStatus.REVERTED == "reverted"


class TestCostOptimizerModels:
    def test_record_defaults(self) -> None:
        r = TelemetryCostRecord()
        assert r.id
        assert r.pipeline_name == ""
        assert r.cost_category == CostCategory.STORAGE
        assert r.optimization_strategy == OptimizationStrategy.DOWNSAMPLE
        assert r.savings_status == SavingsStatus.PROJECTED
        assert r.cost_usd == 0.0
        assert r.projected_savings_usd == 0.0
        assert r.realized_savings_usd == 0.0

    def test_analysis_defaults(self) -> None:
        a = TelemetryCostAnalysis()
        assert a.id
        assert a.pipeline_name == ""
        assert a.total_cost_usd == 0.0
        assert a.total_projected_savings_usd == 0.0
        assert a.total_realized_savings_usd == 0.0

    def test_report_defaults(self) -> None:
        r = TelemetryCostReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_cost_usd == 0.0
        assert r.by_cost_category == {}
        assert r.top_cost_pipelines == []
        assert r.recommendations == []


class TestCostOptimizerAddRecord:
    def test_basic(self) -> None:
        eng = _cost_optimizer_engine()
        r = eng.add_record(
            pipeline_name="metrics-pipeline",
            cost_category=CostCategory.PROCESSING,
            cost_usd=500.0,
            projected_savings_usd=100.0,
        )
        assert r.pipeline_name == "metrics-pipeline"
        assert r.cost_category == CostCategory.PROCESSING
        assert r.cost_usd == 500.0

    def test_eviction_at_max(self) -> None:
        eng = _cost_optimizer_engine(max_records=3)
        for i in range(5):
            eng.add_record(pipeline_name=f"pipe-{i}")
        assert len(eng._records) == 3

    def test_get_record_found(self) -> None:
        eng = _cost_optimizer_engine()
        r = eng.add_record(pipeline_name="pipe-1")
        assert eng.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        eng = _cost_optimizer_engine()
        assert eng.get_record("nonexistent") is None

    def test_list_records_filter(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(pipeline_name="pipe-a", cost_category=CostCategory.STORAGE)
        eng.add_record(pipeline_name="pipe-b", cost_category=CostCategory.EXPORT)
        results = eng.list_records(cost_category=CostCategory.STORAGE)
        assert len(results) == 1


class TestCostOptimizerProcess:
    def test_found(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(
            pipeline_name="pipe-a",
            cost_usd=100.0,
            projected_savings_usd=20.0,
            realized_savings_usd=10.0,
        )
        analysis = eng.process("pipe-a")
        assert analysis is not None
        assert analysis.pipeline_name == "pipe-a"
        assert analysis.total_cost_usd == 100.0
        assert analysis.total_projected_savings_usd == 20.0
        assert analysis.total_realized_savings_usd == 10.0

    def test_not_found(self) -> None:
        eng = _cost_optimizer_engine()
        assert eng.process("nonexistent") is None


class TestCostOptimizerReport:
    def test_populated(self) -> None:
        eng = _cost_optimizer_engine(threshold=50.0)
        eng.add_record(
            pipeline_name="pipe-a",
            cost_usd=200.0,
            projected_savings_usd=50.0,
            realized_savings_usd=20.0,
        )
        report = eng.generate_report()
        assert report.total_records == 1
        assert report.total_cost_usd == 200.0
        assert report.total_projected_savings_usd == 50.0
        assert report.total_realized_savings_usd == 20.0
        assert len(report.top_cost_pipelines) == 1
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = _cost_optimizer_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.total_cost_usd == 0.0


class TestCostOptimizerStats:
    def test_empty(self) -> None:
        eng = _cost_optimizer_engine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0

    def test_populated(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(pipeline_name="pipe-a")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_pipelines"] == 1


class TestCostOptimizerClearData:
    def test_clears(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(pipeline_name="pipe-a")
        eng.process("pipe-a")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestCostOptimizerIdentifyOpportunities:
    def test_finds_expensive_pipelines(self) -> None:
        eng = _cost_optimizer_engine(threshold=100.0)
        eng.add_record(pipeline_name="cheap", cost_usd=10.0)
        eng.add_record(pipeline_name="expensive", cost_usd=500.0)
        results = eng.identify_cost_reduction_opportunities()
        assert len(results) >= 1
        assert results[0]["pipeline_name"] == "expensive"

    def test_finds_unrealized_savings(self) -> None:
        eng = _cost_optimizer_engine(threshold=10000.0)
        eng.add_record(
            pipeline_name="pipe-a",
            cost_usd=50.0,
            projected_savings_usd=30.0,
            realized_savings_usd=10.0,
        )
        results = eng.identify_cost_reduction_opportunities()
        assert len(results) >= 1
        assert results[0]["unrealized_savings_usd"] == 20.0

    def test_empty(self) -> None:
        eng = _cost_optimizer_engine()
        assert eng.identify_cost_reduction_opportunities() == []


class TestCostOptimizerSimulate:
    def test_no_data(self) -> None:
        eng = _cost_optimizer_engine()
        result = eng.simulate_optimization(OptimizationStrategy.DOWNSAMPLE)
        assert result["status"] == "no_data"

    def test_downsample(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(pipeline_name="pipe-a", cost_usd=1000.0)
        result = eng.simulate_optimization(OptimizationStrategy.DOWNSAMPLE)
        assert result["strategy"] == "downsample"
        assert result["projected_daily_savings_usd"] == 400.0
        assert result["reduction_factor"] == 0.40

    def test_compress(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(pipeline_name="pipe-a", cost_usd=1000.0)
        result = eng.simulate_optimization(OptimizationStrategy.COMPRESS)
        assert result["strategy"] == "compress"
        assert result["reduction_factor"] == 0.15


class TestCostOptimizerTrackSavings:
    def test_no_data(self) -> None:
        eng = _cost_optimizer_engine()
        result = eng.track_realized_savings()
        assert result["status"] == "no_data"

    def test_with_data(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(
            pipeline_name="pipe-a",
            projected_savings_usd=100.0,
            realized_savings_usd=60.0,
            savings_status=SavingsStatus.REALIZED,
        )
        eng.add_record(
            pipeline_name="pipe-b",
            projected_savings_usd=50.0,
            realized_savings_usd=10.0,
            savings_status=SavingsStatus.MISSED,
        )
        result = eng.track_realized_savings()
        assert result["total_projected_savings_usd"] == 150.0
        assert result["total_realized_savings_usd"] == 70.0
        assert result["missed_savings_usd"] == 80.0
        assert result["realization_rate_pct"] > 0

    def test_full_realization(self) -> None:
        eng = _cost_optimizer_engine()
        eng.add_record(
            pipeline_name="pipe-a",
            projected_savings_usd=100.0,
            realized_savings_usd=100.0,
            savings_status=SavingsStatus.REALIZED,
        )
        result = eng.track_realized_savings()
        assert result["realization_rate_pct"] == 100.0
        assert result["missed_savings_usd"] == 0.0

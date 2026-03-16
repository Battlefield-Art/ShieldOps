"""Tests for Phase 135 OTel Standards Engines — OtelConfigGeneratorEngine,
OtelHealthMonitorEngine, OtelConnectorRoutingEngine."""

from __future__ import annotations

from shieldops.observability.otel_config_generator_engine import (
    ConfigSection,
    OtelConfigGeneratorAnalysis,
    OtelConfigGeneratorEngine,
    OtelConfigGeneratorRecord,
    OtelConfigGeneratorReport,
    PipelineSignal,
    ValidationStatus,
)
from shieldops.observability.otel_connector_routing_engine import (
    ConnectorType,
    OtelConnectorRoutingAnalysis,
    OtelConnectorRoutingEngine,
    OtelConnectorRoutingRecord,
    OtelConnectorRoutingReport,
    RoutingHealth,
    RoutingStrategy,
)
from shieldops.observability.otel_health_monitor_engine import (
    AlertSeverity,
    CollectorStatus,
    HealthIndicator,
    OtelHealthMonitorAnalysis,
    OtelHealthMonitorEngine,
    OtelHealthMonitorRecord,
    OtelHealthMonitorReport,
)

# ============================================================================
# OtelConfigGeneratorEngine
# ============================================================================


class TestConfigGeneratorEnums:
    def test_config_section_receivers(self) -> None:
        assert ConfigSection.RECEIVERS == "receivers"

    def test_config_section_processors(self) -> None:
        assert ConfigSection.PROCESSORS == "processors"

    def test_config_section_exporters(self) -> None:
        assert ConfigSection.EXPORTERS == "exporters"

    def test_validation_status_valid(self) -> None:
        assert ValidationStatus.VALID == "valid"

    def test_validation_status_warning(self) -> None:
        assert ValidationStatus.WARNING == "warning"

    def test_validation_status_error(self) -> None:
        assert ValidationStatus.ERROR == "error"

    def test_pipeline_signal_traces(self) -> None:
        assert PipelineSignal.TRACES == "traces"

    def test_pipeline_signal_metrics(self) -> None:
        assert PipelineSignal.METRICS == "metrics"

    def test_pipeline_signal_logs(self) -> None:
        assert PipelineSignal.LOGS == "logs"


class TestConfigGeneratorModels:
    def test_record_defaults(self) -> None:
        r = OtelConfigGeneratorRecord()
        assert r.id
        assert r.name == ""
        assert r.config_section == ConfigSection.RECEIVERS
        assert r.validation_status == ValidationStatus.VALID
        assert r.pipeline_signal == PipelineSignal.TRACES
        assert r.score == 0.0
        assert r.component_count == 0
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = OtelConfigGeneratorAnalysis()
        assert a.id
        assert a.name == ""
        assert a.analysis_score == 0.0
        assert a.breached is False
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = OtelConfigGeneratorReport()
        assert r.total_records == 0
        assert r.recommendations == []
        assert r.generated_at > 0


class TestConfigGeneratorEngine:
    def _engine(self, **kw: object) -> OtelConfigGeneratorEngine:
        return OtelConfigGeneratorEngine(**kw)

    def test_init_defaults(self) -> None:
        e = self._engine()
        assert e._max_records == 200000
        assert e._threshold == 50.0

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="otlp-receiver", score=80.0, service="svc-a")
        assert r.name == "otlp-receiver"
        assert r.score == 80.0

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="batch-processor")
        found = e.get_record(r.id)
        assert found is not None
        assert found.name == "batch-processor"

    def test_get_record_not_found(self) -> None:
        e = self._engine()
        assert e.get_record("nonexistent") is None

    def test_list_records_filter_section(self) -> None:
        e = self._engine()
        e.add_record(name="r1", config_section=ConfigSection.RECEIVERS)
        e.add_record(name="r2", config_section=ConfigSection.EXPORTERS)
        results = e.list_records(config_section=ConfigSection.RECEIVERS)
        assert len(results) == 1
        assert results[0].name == "r1"

    def test_list_records_filter_team(self) -> None:
        e = self._engine()
        e.add_record(name="r1", team="platform")
        e.add_record(name="r2", team="security")
        results = e.list_records(team="platform")
        assert len(results) == 1

    def test_add_analysis(self) -> None:
        e = self._engine()
        a = e.add_analysis(name="config-check", analysis_score=75.0)
        assert a.name == "config-check"
        assert a.analysis_score == 75.0

    def test_process_found(self) -> None:
        e = self._engine()
        e.add_record(name="test-cfg", score=60.0)
        result = e.process("test-cfg")
        assert result["status"] == "processed"
        assert result["count"] == 1

    def test_process_not_found(self) -> None:
        e = self._engine()
        result = e.process("missing")
        assert result["status"] == "not_found"

    def test_validate_config_consistency(self) -> None:
        e = self._engine()
        e.add_record(name="r1", config_section=ConfigSection.RECEIVERS, service="svc-a")
        # svc-a only has receivers, missing processors and exporters
        issues = e.validate_config_consistency()
        assert len(issues) == 1
        assert "processors" in issues[0]["missing_sections"]

    def test_detect_pipeline_gaps(self) -> None:
        e = self._engine()
        e.add_record(name="r1", pipeline_signal=PipelineSignal.TRACES, service="svc-a")
        gaps = e.detect_pipeline_gaps()
        assert len(gaps) == 1
        assert "metrics" in gaps[0]["missing_signals"]

    def test_recommend_config_improvements_errors(self) -> None:
        e = self._engine()
        e.add_record(
            name="bad-cfg",
            validation_status=ValidationStatus.ERROR,
            service="svc-a",
        )
        recs = e.recommend_config_improvements()
        assert len(recs) >= 1
        assert recs[0]["priority"] == "high"

    def test_recommend_config_improvements_low_score(self) -> None:
        e = self._engine()
        e.add_record(name="ok-cfg", score=20.0, service="svc-b")
        recs = e.recommend_config_improvements()
        assert any(r["issue"] == "low_score" for r in recs)

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        e.add_record(name="r2", score=30.0)
        report = e.generate_report()
        assert report.total_records == 2
        assert report.gap_count == 1

    def test_generate_report_empty(self) -> None:
        e = self._engine()
        report = e.generate_report()
        assert report.total_records == 0

    def test_get_stats(self) -> None:
        e = self._engine()
        e.add_record(name="r1", service="svc-a", team="t1")
        stats = e.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_teams"] == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.add_analysis(name="a1")
        result = e.clear_data()
        assert result["status"] == "cleared"
        assert e.get_stats()["total_records"] == 0

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=3)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 3

    def test_analyze_distribution(self) -> None:
        e = self._engine()
        e.add_record(name="r1", config_section=ConfigSection.RECEIVERS, score=80.0)
        dist = e.analyze_distribution()
        assert "receivers" in dist

    def test_identify_gaps(self) -> None:
        e = self._engine()
        e.add_record(name="low", score=10.0)
        gaps = e.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self) -> None:
        e = self._engine()
        e.add_record(name="r1", service="svc-a", score=90.0)
        e.add_record(name="r2", service="svc-b", score=30.0)
        ranked = e.rank_by_score()
        assert ranked[0]["service"] == "svc-b"


# ============================================================================
# OtelHealthMonitorEngine
# ============================================================================


class TestHealthMonitorEnums:
    def test_health_indicator_cpu(self) -> None:
        assert HealthIndicator.CPU_USAGE == "cpu_usage"

    def test_health_indicator_memory(self) -> None:
        assert HealthIndicator.MEMORY_USAGE == "memory_usage"

    def test_health_indicator_queue(self) -> None:
        assert HealthIndicator.QUEUE_DEPTH == "queue_depth"

    def test_health_indicator_dropped(self) -> None:
        assert HealthIndicator.DROPPED_DATA == "dropped_data"

    def test_collector_status_healthy(self) -> None:
        assert CollectorStatus.HEALTHY == "healthy"

    def test_collector_status_degraded(self) -> None:
        assert CollectorStatus.DEGRADED == "degraded"

    def test_collector_status_unhealthy(self) -> None:
        assert CollectorStatus.UNHEALTHY == "unhealthy"

    def test_collector_status_unreachable(self) -> None:
        assert CollectorStatus.UNREACHABLE == "unreachable"

    def test_alert_severity_info(self) -> None:
        assert AlertSeverity.INFO == "info"

    def test_alert_severity_warning(self) -> None:
        assert AlertSeverity.WARNING == "warning"

    def test_alert_severity_critical(self) -> None:
        assert AlertSeverity.CRITICAL == "critical"


class TestHealthMonitorModels:
    def test_record_defaults(self) -> None:
        r = OtelHealthMonitorRecord()
        assert r.id
        assert r.health_indicator == HealthIndicator.CPU_USAGE
        assert r.collector_status == CollectorStatus.HEALTHY
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = OtelHealthMonitorAnalysis()
        assert a.id
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = OtelHealthMonitorReport()
        assert r.total_records == 0


class TestHealthMonitorEngine:
    def _engine(self, **kw: object) -> OtelHealthMonitorEngine:
        return OtelHealthMonitorEngine(**kw)

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="cpu-check", score=75.0, collector_id="col-1")
        assert r.name == "cpu-check"
        assert r.collector_id == "col-1"

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="mem-check")
        assert e.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        e = self._engine()
        assert e.get_record("nope") is None

    def test_list_records_filter(self) -> None:
        e = self._engine()
        e.add_record(name="r1", health_indicator=HealthIndicator.CPU_USAGE)
        e.add_record(name="r2", health_indicator=HealthIndicator.MEMORY_USAGE)
        results = e.list_records(health_indicator=HealthIndicator.CPU_USAGE)
        assert len(results) == 1

    def test_detect_unhealthy_collectors(self) -> None:
        e = self._engine()
        e.add_record(
            name="c1",
            collector_id="col-1",
            collector_status=CollectorStatus.UNHEALTHY,
            score=20.0,
        )
        e.add_record(
            name="c2",
            collector_id="col-2",
            collector_status=CollectorStatus.HEALTHY,
            score=90.0,
        )
        unhealthy = e.detect_unhealthy_collectors()
        assert len(unhealthy) == 1
        assert unhealthy[0]["collector_id"] == "col-1"

    def test_analyze_resource_pressure(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            health_indicator=HealthIndicator.CPU_USAGE,
            value=80.0,
        )
        pressure = e.analyze_resource_pressure()
        assert "cpu_usage" in pressure
        assert pressure["cpu_usage"]["avg_value"] == 80.0

    def test_recommend_scaling_actions(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            collector_id="col-1",
            score=10.0,
            collector_status=CollectorStatus.UNHEALTHY,
        )
        recs = e.recommend_scaling_actions()
        assert len(recs) >= 1

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_get_stats(self) -> None:
        e = self._engine()
        e.add_record(name="r1", team="t1", service="svc-a")
        stats = e.get_stats()
        assert stats["unique_teams"] == 1
        assert stats["unique_services"] == 1

    def test_process_found(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        result = e.process("test")
        assert result["status"] == "processed"

    def test_process_not_found(self) -> None:
        e = self._engine()
        result = e.process("missing")
        assert result["status"] == "not_found"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=2)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 2


# ============================================================================
# OtelConnectorRoutingEngine
# ============================================================================


class TestConnectorRoutingEnums:
    def test_connector_type_count(self) -> None:
        assert ConnectorType.COUNT == "count"

    def test_connector_type_spanmetrics(self) -> None:
        assert ConnectorType.SPANMETRICS == "spanmetrics"

    def test_connector_type_forward(self) -> None:
        assert ConnectorType.FORWARD == "forward"

    def test_connector_type_routing(self) -> None:
        assert ConnectorType.ROUTING == "routing"

    def test_routing_strategy_round_robin(self) -> None:
        assert RoutingStrategy.ROUND_ROBIN == "round_robin"

    def test_routing_strategy_content_based(self) -> None:
        assert RoutingStrategy.CONTENT_BASED == "content_based"

    def test_routing_strategy_priority(self) -> None:
        assert RoutingStrategy.PRIORITY == "priority"

    def test_routing_health_optimal(self) -> None:
        assert RoutingHealth.OPTIMAL == "optimal"

    def test_routing_health_suboptimal(self) -> None:
        assert RoutingHealth.SUBOPTIMAL == "suboptimal"

    def test_routing_health_broken(self) -> None:
        assert RoutingHealth.BROKEN == "broken"


class TestConnectorRoutingModels:
    def test_record_defaults(self) -> None:
        r = OtelConnectorRoutingRecord()
        assert r.id
        assert r.connector_type == ConnectorType.FORWARD
        assert r.routing_health == RoutingHealth.OPTIMAL
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = OtelConnectorRoutingAnalysis()
        assert a.id
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = OtelConnectorRoutingReport()
        assert r.total_records == 0


class TestConnectorRoutingEngine:
    def _engine(self, **kw: object) -> OtelConnectorRoutingEngine:
        return OtelConnectorRoutingEngine(**kw)

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="fwd-connector", score=85.0)
        assert r.name == "fwd-connector"

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="cnt-connector")
        assert e.get_record(r.id) is not None

    def test_list_records_filter_type(self) -> None:
        e = self._engine()
        e.add_record(name="r1", connector_type=ConnectorType.COUNT)
        e.add_record(name="r2", connector_type=ConnectorType.FORWARD)
        results = e.list_records(connector_type=ConnectorType.COUNT)
        assert len(results) == 1

    def test_evaluate_routing_efficiency(self) -> None:
        e = self._engine()
        e.add_record(name="conn-a", score=90.0, latency_ms=5.0)
        e.add_record(name="conn-b", score=30.0, latency_ms=50.0)
        results = e.evaluate_routing_efficiency()
        assert len(results) == 2
        assert results[0]["efficiency"] == "high"

    def test_detect_routing_loops(self) -> None:
        e = self._engine()
        e.add_record(
            name="fwd-1",
            connector_type=ConnectorType.FORWARD,
            service="svc-a",
        )
        e.add_record(
            name="fwd-1",
            connector_type=ConnectorType.FORWARD,
            service="svc-a",
        )
        loops = e.detect_routing_loops()
        assert len(loops) == 1
        assert loops[0]["service"] == "svc-a"

    def test_detect_routing_loops_none(self) -> None:
        e = self._engine()
        e.add_record(name="fwd-1", connector_type=ConnectorType.FORWARD, service="s1")
        e.add_record(name="fwd-2", connector_type=ConnectorType.FORWARD, service="s1")
        loops = e.detect_routing_loops()
        assert len(loops) == 0

    def test_optimize_connector_placement_broken(self) -> None:
        e = self._engine()
        e.add_record(
            name="broken-conn",
            routing_health=RoutingHealth.BROKEN,
            service="svc-x",
        )
        recs = e.optimize_connector_placement()
        assert len(recs) >= 1
        assert recs[0]["priority"] == "high"

    def test_optimize_connector_placement_suboptimal(self) -> None:
        e = self._engine()
        e.add_record(
            name="slow-conn",
            routing_health=RoutingHealth.SUBOPTIMAL,
            score=20.0,
            service="svc-y",
        )
        recs = e.optimize_connector_placement()
        assert any(r["priority"] == "medium" for r in recs)

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_get_stats(self) -> None:
        e = self._engine()
        e.add_record(name="r1", team="t1", service="svc-a")
        stats = e.get_stats()
        assert stats["unique_teams"] == 1

    def test_process_found(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        result = e.process("test")
        assert result["status"] == "processed"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=2)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 2

    def test_analyze_distribution(self) -> None:
        e = self._engine()
        e.add_record(name="r1", connector_type=ConnectorType.COUNT, score=70.0)
        dist = e.analyze_distribution()
        assert "count" in dist

    def test_identify_gaps(self) -> None:
        e = self._engine()
        e.add_record(name="low", score=10.0)
        gaps = e.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self) -> None:
        e = self._engine()
        e.add_record(name="r1", service="svc-a", score=90.0)
        e.add_record(name="r2", service="svc-b", score=30.0)
        ranked = e.rank_by_score()
        assert ranked[0]["service"] == "svc-b"

"""Tests for Phase 136 OTel Deployment & Scaling Engines (engines 1-3)."""

from __future__ import annotations

import pytest

from shieldops.observability.otel_deployment_tracker_engine import (
    ClusterRegion,
    DeploymentPhase,
    DeploymentType,
    OtelDeploymentTrackerEngine,
    OtelDeploymentTrackerRecord,
    OtelDeploymentTrackerAnalysis,
    OtelDeploymentTrackerReport,
)
from shieldops.observability.otel_pipeline_throughput_engine import (
    BottleneckLocation,
    SignalType,
    ThroughputStatus,
    OtelPipelineThroughputEngine,
    OtelPipelineThroughputRecord,
    OtelPipelineThroughputAnalysis,
    OtelPipelineThroughputReport,
)
from shieldops.observability.otel_extension_manager_engine import (
    ExtensionPriority,
    ExtensionStatus,
    ExtensionType,
    OtelExtensionManagerEngine,
    OtelExtensionManagerRecord,
    OtelExtensionManagerAnalysis,
    OtelExtensionManagerReport,
)


# ============================================================
# OtelDeploymentTrackerEngine Tests
# ============================================================


class TestDeploymentTrackerEnums:
    def test_deployment_phase_values(self):
        assert DeploymentPhase.PLANNED == "planned"
        assert DeploymentPhase.DEPLOYING == "deploying"
        assert DeploymentPhase.RUNNING == "running"
        assert DeploymentPhase.DEGRADED == "degraded"
        assert DeploymentPhase.FAILED == "failed"

    def test_deployment_type_values(self):
        assert DeploymentType.DAEMONSET == "daemonset"
        assert DeploymentType.DEPLOYMENT == "deployment"
        assert DeploymentType.SIDECAR == "sidecar"

    def test_cluster_region_values(self):
        assert ClusterRegion.US_EAST == "us_east"
        assert ClusterRegion.US_WEST == "us_west"
        assert ClusterRegion.EU_WEST == "eu_west"
        assert ClusterRegion.AP_SOUTH == "ap_south"


class TestDeploymentTrackerModels:
    def test_record_defaults(self):
        r = OtelDeploymentTrackerRecord()
        assert r.id
        assert r.name == ""
        assert r.deployment_phase == DeploymentPhase.PLANNED
        assert r.deployment_type == DeploymentType.DAEMONSET
        assert r.cluster_region == ClusterRegion.US_EAST
        assert r.score == 0.0
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = OtelDeploymentTrackerAnalysis()
        assert a.id
        assert a.breached is False

    def test_report_defaults(self):
        r = OtelDeploymentTrackerReport()
        assert r.total_records == 0
        assert r.by_deployment_phase == {}


class TestDeploymentTrackerEngine:
    def setup_method(self):
        self.engine = OtelDeploymentTrackerEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100
        assert self.engine._threshold == 50.0

    def test_add_record(self):
        r = self.engine.add_record(name="collector-prod", score=80.0, service="api")
        assert r.name == "collector-prod"
        assert r.score == 80.0
        assert len(self.engine._records) == 1

    def test_get_record(self):
        r = self.engine.add_record(name="test", service="svc1")
        found = self.engine.get_record(r.id)
        assert found is not None
        assert found.name == "test"

    def test_get_record_not_found(self):
        assert self.engine.get_record("nonexistent") is None

    def test_list_records_no_filter(self):
        self.engine.add_record(name="r1", service="s1")
        self.engine.add_record(name="r2", service="s2")
        assert len(self.engine.list_records()) == 2

    def test_list_records_by_phase(self):
        self.engine.add_record(name="r1", deployment_phase=DeploymentPhase.RUNNING)
        self.engine.add_record(name="r2", deployment_phase=DeploymentPhase.FAILED)
        result = self.engine.list_records(deployment_phase=DeploymentPhase.RUNNING)
        assert len(result) == 1
        assert result[0].name == "r1"

    def test_list_records_by_type(self):
        self.engine.add_record(name="r1", deployment_type=DeploymentType.SIDECAR)
        self.engine.add_record(name="r2", deployment_type=DeploymentType.DAEMONSET)
        result = self.engine.list_records(deployment_type=DeploymentType.SIDECAR)
        assert len(result) == 1

    def test_list_records_by_team(self):
        self.engine.add_record(name="r1", team="platform")
        self.engine.add_record(name="r2", team="security")
        result = self.engine.list_records(team="platform")
        assert len(result) == 1

    def test_list_records_limit(self):
        for i in range(10):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine.list_records(limit=3)) == 3

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="analysis1", analysis_score=75.0)
        assert a.name == "analysis1"
        assert len(self.engine._analyses) == 1

    def test_ring_buffer_records(self):
        engine = OtelDeploymentTrackerEngine(max_records=3)
        for i in range(5):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 3
        assert engine._records[0].name == "r2"

    def test_ring_buffer_analyses(self):
        engine = OtelDeploymentTrackerEngine(max_records=2)
        for i in range(4):
            engine.add_analysis(name=f"a{i}")
        assert len(engine._analyses) == 2

    def test_track_deployment_health(self):
        self.engine.add_record(
            name="c1", cluster_region=ClusterRegion.US_EAST,
            deployment_phase=DeploymentPhase.RUNNING,
        )
        self.engine.add_record(
            name="c2", cluster_region=ClusterRegion.US_EAST,
            deployment_phase=DeploymentPhase.FAILED,
        )
        self.engine.add_record(
            name="c3", cluster_region=ClusterRegion.EU_WEST,
            deployment_phase=DeploymentPhase.RUNNING,
        )
        result = self.engine.track_deployment_health()
        assert len(result) == 2
        us_east = [r for r in result if r["region"] == "us_east"][0]
        assert us_east["healthy"] == 1
        assert us_east["failed"] == 1
        assert us_east["health_pct"] == 50.0

    def test_track_deployment_health_empty(self):
        assert self.engine.track_deployment_health() == []

    def test_detect_config_drift_across_clusters(self):
        self.engine.add_record(
            name="c1", service="api", cluster_region=ClusterRegion.US_EAST,
            config_version="v1.0",
        )
        self.engine.add_record(
            name="c2", service="api", cluster_region=ClusterRegion.EU_WEST,
            config_version="v1.1",
        )
        drifts = self.engine.detect_config_drift_across_clusters()
        assert len(drifts) == 1
        assert drifts[0]["drift_count"] == 2

    def test_detect_config_drift_no_drift(self):
        self.engine.add_record(
            name="c1", service="api", cluster_region=ClusterRegion.US_EAST,
            config_version="v1.0",
        )
        self.engine.add_record(
            name="c2", service="api", cluster_region=ClusterRegion.EU_WEST,
            config_version="v1.0",
        )
        assert len(self.engine.detect_config_drift_across_clusters()) == 0

    def test_recommend_deployment_upgrades_failed(self):
        self.engine.add_record(
            name="c1", deployment_phase=DeploymentPhase.FAILED,
            service="api", cluster_region=ClusterRegion.US_EAST,
        )
        recs = self.engine.recommend_deployment_upgrades()
        assert len(recs) == 1
        assert recs[0]["priority"] == "critical"

    def test_recommend_deployment_upgrades_degraded(self):
        self.engine.add_record(
            name="c1", deployment_phase=DeploymentPhase.DEGRADED,
            service="api", score=80.0,
        )
        recs = self.engine.recommend_deployment_upgrades()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_deployment_upgrades_low_score(self):
        self.engine.add_record(
            name="c1", deployment_phase=DeploymentPhase.RUNNING,
            service="api", score=20.0,
        )
        recs = self.engine.recommend_deployment_upgrades()
        assert len(recs) == 1
        assert recs[0]["priority"] == "medium"

    def test_analyze_distribution(self):
        self.engine.add_record(name="r1", score=80.0, deployment_phase=DeploymentPhase.RUNNING)
        self.engine.add_record(name="r2", score=60.0, deployment_phase=DeploymentPhase.RUNNING)
        dist = self.engine.analyze_distribution()
        assert "running" in dist
        assert dist["running"]["count"] == 2
        assert dist["running"]["avg_score"] == 70.0

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=30.0)
        self.engine.add_record(name="r2", score=80.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1
        assert gaps[0]["name"] == "r1"

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=30.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"
        assert ranked[1]["service"] == "high"

    def test_process_found(self):
        self.engine.add_record(name="test", score=70.0, service="api")
        result = self.engine.process("test")
        assert result["status"] == "processed"
        assert result["count"] == 1

    def test_process_not_found(self):
        result = self.engine.process("missing")
        assert result["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0, deployment_phase=DeploymentPhase.RUNNING)
        self.engine.add_record(name="r2", score=30.0, deployment_phase=DeploymentPhase.FAILED)
        report = self.engine.generate_report()
        assert report.total_records == 2
        assert report.gap_count == 1
        assert "running" in report.by_deployment_phase

    def test_generate_report_empty(self):
        report = self.engine.generate_report()
        assert report.total_records == 0
        assert report.avg_score == 0.0

    def test_generate_report_healthy(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert "is healthy" in report.recommendations[0]

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.add_analysis(name="a1")
        result = self.engine.clear_data()
        assert result["status"] == "cleared"
        assert len(self.engine._records) == 0
        assert len(self.engine._analyses) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", service="api", team="platform")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_teams"] == 1
        assert stats["unique_services"] == 1
        assert stats["threshold"] == 50.0


# ============================================================
# OtelPipelineThroughputEngine Tests
# ============================================================


class TestPipelineThroughputEnums:
    def test_signal_type_values(self):
        assert SignalType.TRACES == "traces"
        assert SignalType.METRICS == "metrics"
        assert SignalType.LOGS == "logs"

    def test_throughput_status_values(self):
        assert ThroughputStatus.NORMAL == "normal"
        assert ThroughputStatus.THROTTLED == "throttled"
        assert ThroughputStatus.BACKPRESSURED == "backpressured"
        assert ThroughputStatus.DROPPING == "dropping"

    def test_bottleneck_location_values(self):
        assert BottleneckLocation.RECEIVER == "receiver"
        assert BottleneckLocation.PROCESSOR == "processor"
        assert BottleneckLocation.EXPORTER == "exporter"


class TestPipelineThroughputModels:
    def test_record_defaults(self):
        r = OtelPipelineThroughputRecord()
        assert r.id
        assert r.signal_type == SignalType.TRACES
        assert r.events_per_second == 0.0
        assert r.drop_rate == 0.0

    def test_analysis_defaults(self):
        a = OtelPipelineThroughputAnalysis()
        assert a.id
        assert a.breached is False

    def test_report_defaults(self):
        r = OtelPipelineThroughputReport()
        assert r.total_records == 0


class TestPipelineThroughputEngine:
    def setup_method(self):
        self.engine = OtelPipelineThroughputEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(
            name="pipeline1", signal_type=SignalType.TRACES,
            events_per_second=1000.0, score=80.0,
        )
        assert r.name == "pipeline1"
        assert r.events_per_second == 1000.0

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("missing") is None

    def test_list_records_by_signal_type(self):
        self.engine.add_record(name="r1", signal_type=SignalType.TRACES)
        self.engine.add_record(name="r2", signal_type=SignalType.LOGS)
        result = self.engine.list_records(signal_type=SignalType.TRACES)
        assert len(result) == 1

    def test_list_records_by_status(self):
        self.engine.add_record(name="r1", throughput_status=ThroughputStatus.NORMAL)
        self.engine.add_record(name="r2", throughput_status=ThroughputStatus.DROPPING)
        result = self.engine.list_records(throughput_status=ThroughputStatus.DROPPING)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1", analysis_score=60.0)
        assert a.analysis_score == 60.0

    def test_ring_buffer(self):
        engine = OtelPipelineThroughputEngine(max_records=2)
        for i in range(4):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_identify_throughput_bottlenecks(self):
        self.engine.add_record(
            name="r1", throughput_status=ThroughputStatus.DROPPING,
            bottleneck_location=BottleneckLocation.EXPORTER,
            signal_type=SignalType.TRACES, drop_rate=15.0,
        )
        bottlenecks = self.engine.identify_throughput_bottlenecks()
        assert len(bottlenecks) == 1
        assert bottlenecks[0]["location"] == "exporter"
        assert bottlenecks[0]["severity"] == "critical"

    def test_identify_throughput_bottlenecks_empty(self):
        self.engine.add_record(
            name="r1", throughput_status=ThroughputStatus.NORMAL,
        )
        assert len(self.engine.identify_throughput_bottlenecks()) == 0

    def test_compute_pipeline_efficiency(self):
        self.engine.add_record(
            name="r1", service="api", signal_type=SignalType.TRACES,
            throughput_status=ThroughputStatus.NORMAL, events_per_second=500.0,
        )
        self.engine.add_record(
            name="r2", service="api", signal_type=SignalType.TRACES,
            throughput_status=ThroughputStatus.DROPPING, events_per_second=200.0,
        )
        result = self.engine.compute_pipeline_efficiency()
        assert len(result) == 1
        assert result[0]["pipeline"] == "api:traces"
        assert result[0]["efficiency_score"] == 50.0

    def test_recommend_throughput_improvements_dropping(self):
        self.engine.add_record(
            name="r1", throughput_status=ThroughputStatus.DROPPING,
            service="api", drop_rate=5.0,
        )
        recs = self.engine.recommend_throughput_improvements()
        assert len(recs) == 1
        assert recs[0]["priority"] == "critical"

    def test_recommend_throughput_improvements_backpressured(self):
        self.engine.add_record(
            name="r1", throughput_status=ThroughputStatus.BACKPRESSURED,
            service="api",
        )
        recs = self.engine.recommend_throughput_improvements()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_throughput_improvements_low_score(self):
        self.engine.add_record(
            name="r1", throughput_status=ThroughputStatus.NORMAL,
            service="api", score=20.0,
        )
        recs = self.engine.recommend_throughput_improvements()
        assert len(recs) == 1
        assert recs[0]["priority"] == "medium"

    def test_analyze_distribution(self):
        self.engine.add_record(name="r1", score=80.0, signal_type=SignalType.LOGS)
        dist = self.engine.analyze_distribution()
        assert "logs" in dist
        assert dist["logs"]["count"] == 1

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=30.0)
        self.engine.add_record(name="r2", score=80.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_process_found(self):
        self.engine.add_record(name="test", score=70.0)
        result = self.engine.process("test")
        assert result["status"] == "processed"

    def test_process_not_found(self):
        result = self.engine.process("nope")
        assert result["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1
        assert "is healthy" in report.recommendations[0]

    def test_generate_report_with_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        report = self.engine.generate_report()
        assert report.gap_count == 1

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.add_analysis(name="a1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="t1", service="s1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert "signal_type_distribution" in stats


# ============================================================
# OtelExtensionManagerEngine Tests
# ============================================================


class TestExtensionManagerEnums:
    def test_extension_type_values(self):
        assert ExtensionType.HEALTH_CHECK == "health_check"
        assert ExtensionType.PPROF == "pprof"
        assert ExtensionType.ZPAGES == "zpages"
        assert ExtensionType.BEARERTOKENAUTH == "bearertokenauth"
        assert ExtensionType.OAUTH2CLIENT == "oauth2client"

    def test_extension_status_values(self):
        assert ExtensionStatus.ENABLED == "enabled"
        assert ExtensionStatus.DISABLED == "disabled"
        assert ExtensionStatus.ERROR == "error"

    def test_extension_priority_values(self):
        assert ExtensionPriority.REQUIRED == "required"
        assert ExtensionPriority.RECOMMENDED == "recommended"
        assert ExtensionPriority.OPTIONAL == "optional"


class TestExtensionManagerModels:
    def test_record_defaults(self):
        r = OtelExtensionManagerRecord()
        assert r.id
        assert r.config_valid is True
        assert r.port == 0

    def test_analysis_defaults(self):
        a = OtelExtensionManagerAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = OtelExtensionManagerReport()
        assert r.by_extension_type == {}


class TestExtensionManagerEngine:
    def setup_method(self):
        self.engine = OtelExtensionManagerEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(
            name="health_check_ext", extension_type=ExtensionType.HEALTH_CHECK,
            port=13133, score=90.0,
        )
        assert r.port == 13133

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("xxx") is None

    def test_list_records_by_type(self):
        self.engine.add_record(name="r1", extension_type=ExtensionType.PPROF)
        self.engine.add_record(name="r2", extension_type=ExtensionType.ZPAGES)
        result = self.engine.list_records(extension_type=ExtensionType.PPROF)
        assert len(result) == 1

    def test_list_records_by_status(self):
        self.engine.add_record(name="r1", extension_status=ExtensionStatus.ENABLED)
        self.engine.add_record(name="r2", extension_status=ExtensionStatus.ERROR)
        result = self.engine.list_records(extension_status=ExtensionStatus.ERROR)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self):
        engine = OtelExtensionManagerEngine(max_records=2)
        for i in range(5):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_audit_extension_coverage(self):
        self.engine.add_record(
            name="hc", extension_type=ExtensionType.HEALTH_CHECK,
            extension_status=ExtensionStatus.ENABLED, service="api",
        )
        self.engine.add_record(
            name="pp", extension_type=ExtensionType.PPROF,
            extension_status=ExtensionStatus.DISABLED, service="api",
        )
        result = self.engine.audit_extension_coverage()
        assert len(result) == 1
        assert "health_check" in result[0]["enabled"]
        assert "pprof" in result[0]["disabled"]

    def test_detect_missing_extensions(self):
        self.engine.add_record(
            name="hc", extension_type=ExtensionType.HEALTH_CHECK,
            extension_priority=ExtensionPriority.REQUIRED,
            extension_status=ExtensionStatus.DISABLED, service="api",
        )
        result = self.engine.detect_missing_extensions()
        assert len(result) == 1
        assert result[0]["count"] == 1

    def test_detect_missing_extensions_all_enabled(self):
        self.engine.add_record(
            name="hc", extension_type=ExtensionType.HEALTH_CHECK,
            extension_priority=ExtensionPriority.REQUIRED,
            extension_status=ExtensionStatus.ENABLED, service="api",
        )
        assert len(self.engine.detect_missing_extensions()) == 0

    def test_recommend_extension_config_error(self):
        self.engine.add_record(
            name="ext1", extension_status=ExtensionStatus.ERROR, service="api",
        )
        recs = self.engine.recommend_extension_config()
        assert len(recs) == 1
        assert recs[0]["priority"] == "critical"

    def test_recommend_extension_config_disabled_required(self):
        self.engine.add_record(
            name="ext1", extension_status=ExtensionStatus.DISABLED,
            extension_priority=ExtensionPriority.REQUIRED, service="api", score=80.0,
        )
        recs = self.engine.recommend_extension_config()
        assert any(r["priority"] == "high" for r in recs)

    def test_recommend_extension_config_low_score(self):
        self.engine.add_record(
            name="ext1", extension_status=ExtensionStatus.ENABLED,
            extension_priority=ExtensionPriority.OPTIONAL, service="api", score=20.0,
        )
        recs = self.engine.recommend_extension_config()
        assert len(recs) == 1
        assert recs[0]["priority"] == "medium"

    def test_analyze_distribution(self):
        self.engine.add_record(name="r1", score=80.0, extension_type=ExtensionType.ZPAGES)
        dist = self.engine.analyze_distribution()
        assert "zpages" in dist

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_process_found(self):
        self.engine.add_record(name="ext", score=70.0)
        assert self.engine.process("ext")["status"] == "processed"

    def test_process_not_found(self):
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_empty(self):
        report = self.engine.generate_report()
        assert report.avg_score == 0.0

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="t1", service="s1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert "extension_type_distribution" in stats

"""Tests for shieldops.agents.performance_profiler."""

from __future__ import annotations

from shieldops.agents.performance_profiler.models import (
    BottleneckType,
    ImpactLevel,
    PerformanceProfilerState,
    ProfilerStage,
)


class TestEnums:
    def test_profilerstage_collect_traces(self):
        assert ProfilerStage.COLLECT_TRACES == "collect_traces"

    def test_profilerstage_analyze_latency(self):
        assert ProfilerStage.ANALYZE_LATENCY == "analyze_latency"

    def test_profilerstage_detect_bottlenecks(self):
        assert ProfilerStage.DETECT_BOTTLENECKS == "detect_bottlenecks"

    def test_profilerstage_identify_contention(self):
        assert ProfilerStage.IDENTIFY_CONTENTION == "identify_contention"

    def test_bottlenecktype_database_query(self):
        assert BottleneckType.DATABASE_QUERY == "database_query"

    def test_bottlenecktype_external_api(self):
        assert BottleneckType.EXTERNAL_API == "external_api"

    def test_bottlenecktype_cpu_bound(self):
        assert BottleneckType.CPU_BOUND == "cpu_bound"

    def test_bottlenecktype_memory_allocation(self):
        assert BottleneckType.MEMORY_ALLOCATION == "memory_allocation"

    def test_impactlevel_critical(self):
        assert ImpactLevel.CRITICAL == "critical"

    def test_impactlevel_high(self):
        assert ImpactLevel.HIGH == "high"

    def test_impactlevel_medium(self):
        assert ImpactLevel.MEDIUM == "medium"

    def test_impactlevel_low(self):
        assert ImpactLevel.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = PerformanceProfilerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.performance_profiler.graph import (
            create_performance_profiler_graph,
        )

        sg = create_performance_profiler_graph()
        assert sg.compile() is not None

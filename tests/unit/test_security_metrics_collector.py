"""Tests for security_metrics_collector."""

from __future__ import annotations

from shieldops.agents.security_metrics_collector.models import (
    MetricCategory,
    MetricsStage,
    PerformanceTrend,
    SecurityMetricsCollectorState,
)


class TestEnums:
    def test_collector_stage(self) -> None:
        assert MetricsStage.DEFINE_METRICS == "define_metrics"
        assert len(MetricsStage) >= 3

    def test_metric_category(self) -> None:
        assert MetricCategory.DETECTION == "detection"
        assert len(MetricCategory) >= 3

    def test_performance_trend(self) -> None:
        assert PerformanceTrend.IMPROVING == "improving"
        assert len(PerformanceTrend) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SecurityMetricsCollectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SecurityMetricsCollectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

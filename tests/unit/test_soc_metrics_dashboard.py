"""Tests for soc_metrics_dashboard."""

from __future__ import annotations

from shieldops.agents.soc_metrics_dashboard.models import (
    MetricCategory,
    MetricsStage,
    SocMetricsDashboardState,
)


class TestEnums:
    def test_metriccategory(self) -> None:
        assert MetricCategory.DETECTION == "detection"
        assert len(MetricCategory) >= 3

    def test_metricsstage(self) -> None:
        assert MetricsStage.COLLECT_DATA == "collect_data"
        assert len(MetricsStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SocMetricsDashboardState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SocMetricsDashboardState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

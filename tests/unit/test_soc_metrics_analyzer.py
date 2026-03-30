"""Unit tests for soc_metrics_analyzer agent models."""

from __future__ import annotations

from shieldops.agents.soc_metrics_analyzer.models import (
    MetricCategory,
    PerformanceTrend,
    SMAStage,
    SOCMetricsAnalyzerState,
)


class TestEnums:
    def test_sma_stage_values(self) -> None:
        assert SMAStage.COLLECT_METRICS == "collect_metrics"
        assert SMAStage.DETECT_BOTTLENECKS == "detect_bottlenecks"
        assert SMAStage.REPORT == "report"

    def test_metric_category(self) -> None:
        assert MetricCategory.DETECTION == "detection"
        assert MetricCategory.RESPONSE == "response"
        assert MetricCategory.EFFICIENCY == "efficiency"

    def test_performance_trend(self) -> None:
        assert PerformanceTrend.IMPROVING == "improving"
        assert PerformanceTrend.DECLINING == "declining"


class TestState:
    def test_default_state(self) -> None:
        state = SOCMetricsAnalyzerState()
        assert state.request_id == ""
        assert state.stage == SMAStage.COLLECT_METRICS
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = SOCMetricsAnalyzerState(
            request_id="req-001",
            stage=SMAStage.DETECT_BOTTLENECKS,
        )
        assert state.stage == SMAStage.DETECT_BOTTLENECKS

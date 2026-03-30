"""Tests for performance_baseline_engine."""

from __future__ import annotations

from shieldops.agents.performance_baseline_engine.models import (
    BaselineMetric,
    DeviationSeverity,
    PBEStage,
    PerformanceBaselineEngineState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert PBEStage.COLLECT_METRICS == "collect_metrics"
        assert len(PBEStage) >= 3

    def test_baseline_metric(self) -> None:
        assert BaselineMetric.LATENCY_P50 == "latency_p50"
        assert len(BaselineMetric) >= 3

    def test_deviation_severity(self) -> None:
        assert DeviationSeverity.CRITICAL == "critical"
        assert len(DeviationSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PerformanceBaselineEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PerformanceBaselineEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

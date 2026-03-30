"""Tests for behavioral_analytics_engine."""

from __future__ import annotations

from shieldops.agents.behavioral_analytics_engine.models import (
    AnomalyScore,
    BAEStage,
    BehavioralAnalyticsEngineState,
    BehaviorType,
)


class TestEnums:
    def test_stage(self) -> None:
        assert BAEStage.COLLECT_TELEMETRY == "collect_telemetry"
        assert len(BAEStage) >= 3

    def test_behavior_type(self) -> None:
        assert BehaviorType.LOGIN == "login"
        assert len(BehaviorType) >= 3

    def test_anomaly_score(self) -> None:
        assert AnomalyScore.CRITICAL == "critical"
        assert len(AnomalyScore) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = BehavioralAnalyticsEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = BehavioralAnalyticsEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

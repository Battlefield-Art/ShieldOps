"""Tests for rate_limit_enforcer."""

from __future__ import annotations

from shieldops.agents.rate_limit_enforcer.models import (
    LimitAction,
    RateLimitEnforcerState,
    RLEStage,
    TrafficPattern,
)


class TestEnums:
    def test_stage(self) -> None:
        assert RLEStage.MONITOR_TRAFFIC == "monitor_traffic"
        assert len(RLEStage) >= 3

    def test_traffic_pattern(self) -> None:
        assert TrafficPattern.BURST == "burst"
        assert len(TrafficPattern) >= 3

    def test_limit_action(self) -> None:
        assert LimitAction.BLOCK == "block"
        assert len(LimitAction) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = RateLimitEnforcerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = RateLimitEnforcerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

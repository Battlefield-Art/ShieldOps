"""Unit tests for api_rate_limiter agent."""

from __future__ import annotations

from shieldops.agents.api_rate_limiter.models import (
    AbuseDetection,
    AbusePattern,
    ActionType,
    APIRateLimiterState,
    ClientProfile,
    RateLimitStage,
)
from shieldops.agents.api_rate_limiter.tools import APIRateLimiterToolkit


class TestEnums:
    def test_abusepattern_values(self) -> None:
        assert AbusePattern.CREDENTIAL_STUFFING == "credential_stuffing"
        assert len(AbusePattern) >= 3

    def test_actiontype_values(self) -> None:
        assert ActionType.ALLOW == "allow"
        assert len(ActionType) >= 3

    def test_ratelimitstage_values(self) -> None:
        assert RateLimitStage.INGEST == "ingest"
        assert len(RateLimitStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = APIRateLimiterState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = APIRateLimiterState(request_id="t-1", tenant_id="t-1")
        assert state.request_id == "t-1"


class TestAbuseDetection:
    def test_defaults(self) -> None:
        obj = AbuseDetection()
        assert obj is not None


class TestClientProfile:
    def test_defaults(self) -> None:
        obj = ClientProfile()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        toolkit = APIRateLimiterToolkit()
        assert toolkit is not None

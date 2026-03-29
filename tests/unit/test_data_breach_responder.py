"""Tests for data_breach_responder."""

from __future__ import annotations

from shieldops.agents.data_breach_responder.models import (
    BreachType,
    DataBreachResponderState,
    NotificationStatus,
    ResponseStage,
)


class TestEnums:
    def test_breachtype(self) -> None:
        assert BreachType.UNAUTHORIZED_ACCESS == "unauthorized_access"
        assert len(BreachType) >= 3

    def test_notificationstatus(self) -> None:
        assert NotificationStatus.PENDING == "pending"
        assert len(NotificationStatus) >= 3

    def test_responsestage(self) -> None:
        assert ResponseStage.DETECT_BREACH == "detect_breach"
        assert len(ResponseStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DataBreachResponderState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DataBreachResponderState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

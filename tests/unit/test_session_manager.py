"""Tests for session_manager."""

from __future__ import annotations

from shieldops.agents.session_manager.models import (
    SessionManagerState,
    SessionRisk,
    SessionType,
    SMStage,
)


class TestEnums:
    def test_stage(self) -> None:
        assert SMStage.DISCOVER_SESSIONS == "discover_sessions"
        assert len(SMStage) >= 3

    def test_session_type(self) -> None:
        assert SessionType.WEB == "web"
        assert len(SessionType) >= 3

    def test_session_risk(self) -> None:
        assert SessionRisk.COMPROMISED == "compromised"
        assert len(SessionRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SessionManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SessionManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

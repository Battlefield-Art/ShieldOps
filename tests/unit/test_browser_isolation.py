"""Unit tests for browser_isolation."""

from __future__ import annotations

from shieldops.agents.browser_isolation.models import (
    BrowserIsolationState,
    IsolationAction,
    IsolationStage,
    SessionRisk,
)


class TestEnums:
    def test_isolationaction(self) -> None:
        assert IsolationAction.TERMINATE == "terminate"
        assert len(IsolationAction) >= 3

    def test_isolationstage(self) -> None:
        assert IsolationStage.COLLECT_SESSIONS == "collect_sessions"
        assert len(IsolationStage) >= 3

    def test_sessionrisk(self) -> None:
        assert SessionRisk.CRITICAL == "critical"
        assert len(SessionRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = BrowserIsolationState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = BrowserIsolationState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

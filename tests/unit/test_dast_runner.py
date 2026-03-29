"""Unit tests for dast_runner."""

from __future__ import annotations

from shieldops.agents.dast_runner.models import (
    AttackType,
    DASTRunnerState,
    DASTStage,
    ScanScope,
)


class TestEnums:
    def test_attacktype(self) -> None:
        assert AttackType.AUTH_BYPASS == "auth_bypass"
        assert len(AttackType) >= 3

    def test_daststage(self) -> None:
        assert DASTStage.DISCOVER_ENDPOINTS == "discover_endpoints"
        assert len(DASTStage) >= 3

    def test_scanscope(self) -> None:
        assert ScanScope.FULL == "full"
        assert len(ScanScope) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DASTRunnerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DASTRunnerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

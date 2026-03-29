"""Tests for iso27001_assessor."""

from __future__ import annotations

from shieldops.agents.iso27001_assessor.models import (
    ControlDomain,
    ISO27001AssessorState,
    ISOStage,
    MaturityLevel,
)


class TestEnums:
    def test_controldomain(self) -> None:
        assert ControlDomain.INFORMATION_SECURITY_POLICIES == "information_security_policies"
        assert len(ControlDomain) >= 3

    def test_isostage(self) -> None:
        assert ISOStage.SCOPE_ISMS == "scope_isms"
        assert len(ISOStage) >= 3

    def test_maturitylevel(self) -> None:
        assert MaturityLevel.INITIAL == "initial"
        assert len(MaturityLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ISO27001AssessorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ISO27001AssessorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

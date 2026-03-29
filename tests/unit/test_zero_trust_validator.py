"""Tests for zero_trust_validator."""

from __future__ import annotations

from shieldops.agents.zero_trust_validator.models import (
    MaturityLevel,
    ValidationStage,
    ZeroTrustValidatorState,
)


class TestEnums:
    def test_maturitylevel(self) -> None:
        assert MaturityLevel.TRADITIONAL == "traditional"
        assert len(MaturityLevel) >= 3

    def test_validationstage(self) -> None:
        assert ValidationStage.INVENTORY_ASSETS == "inventory_assets"
        assert len(ValidationStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ZeroTrustValidatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ZeroTrustValidatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

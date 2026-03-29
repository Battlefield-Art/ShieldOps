"""Tests for adversary_emulator."""

from __future__ import annotations

from shieldops.agents.adversary_emulator.models import (
    AdversaryEmulatorState,
    AdversaryGroup,
    EmulationResult,
    EmulationStage,
)


class TestEnums:
    def test_adversarygroup(self) -> None:
        assert AdversaryGroup.APT29 == "apt29"
        assert len(AdversaryGroup) >= 3

    def test_emulationresult(self) -> None:
        assert EmulationResult.DETECTED == "detected"
        assert len(EmulationResult) >= 3

    def test_emulationstage(self) -> None:
        assert EmulationStage.SELECT_ADVERSARY == "select_adversary"
        assert len(EmulationStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = AdversaryEmulatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = AdversaryEmulatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

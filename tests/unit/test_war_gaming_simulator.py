"""Tests for war_gaming_simulator."""

from __future__ import annotations

from shieldops.agents.war_gaming_simulator.models import (
    GameOutcome,
    SimulationStage,
    WarGamingSimulatorState,
)


class TestEnums:
    def test_gameoutcome(self) -> None:
        assert GameOutcome.BLUE_WIN == "blue_win"
        assert len(GameOutcome) >= 3

    def test_simulationstage(self) -> None:
        assert SimulationStage.DESIGN_SCENARIO == "design_scenario"
        assert len(SimulationStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = WarGamingSimulatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = WarGamingSimulatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

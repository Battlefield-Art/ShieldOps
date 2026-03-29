"""Tests for data_sovereignty_enforcer."""

from __future__ import annotations

from shieldops.agents.data_sovereignty_enforcer.models import (
    DataSovereigntyEnforcerState,
    Jurisdiction,
    SovereigntyStage,
    TransferMechanism,
)


class TestEnums:
    def test_sovereignty_stage(self) -> None:
        assert SovereigntyStage.DISCOVER_DATA_FLOWS == "discover_data_flows"
        assert len(SovereigntyStage) >= 3

    def test_jurisdiction(self) -> None:
        assert Jurisdiction.EU == "eu"
        assert len(Jurisdiction) >= 3

    def test_transfer_mechanism(self) -> None:
        assert TransferMechanism.ADEQUACY_DECISION == "adequacy_decision"
        assert len(TransferMechanism) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = DataSovereigntyEnforcerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = DataSovereigntyEnforcerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

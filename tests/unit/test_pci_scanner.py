"""Tests for pci_scanner."""

from __future__ import annotations

from shieldops.agents.pci_scanner.models import (
    PCIScannerState,
    PCIStage,
    Requirement,
    ScanStatus,
)


class TestEnums:
    def test_pcistage(self) -> None:
        assert PCIStage.CDE_MAPPING == "cde_mapping"
        assert len(PCIStage) >= 3

    def test_requirement(self) -> None:
        assert Requirement.NETWORK_SECURITY == "network_security"
        assert len(Requirement) >= 3

    def test_scanstatus(self) -> None:
        assert ScanStatus.PASSED == "passed"
        assert len(ScanStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PCIScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PCIScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

"""Unit tests for patch_compliance_checker."""

from __future__ import annotations

from shieldops.agents.patch_compliance_checker.models import (
    PatchComplianceCheckerState,
    PatchSeverity,
    PatchStage,
    PatchStatus,
)


class TestEnums:
    def test_patchseverity(self) -> None:
        assert PatchSeverity.CRITICAL == "critical"
        assert len(PatchSeverity) >= 3

    def test_patchstage(self) -> None:
        assert PatchStage.INVENTORY_SYSTEMS == "inventory_systems"
        assert len(PatchStage) >= 3

    def test_patchstatus(self) -> None:
        assert PatchStatus.MISSING == "missing"
        assert len(PatchStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PatchComplianceCheckerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PatchComplianceCheckerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

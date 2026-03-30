"""Tests for infrastructure_drift_detector."""

from __future__ import annotations

from shieldops.agents.infrastructure_drift_detector.models import (
    DriftType,
    IDDStage,
    InfraLayer,
    InfrastructureDriftDetectorState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert IDDStage.SCAN_INFRASTRUCTURE == "scan_infrastructure"
        assert len(IDDStage) >= 3

    def test_infra_layer(self) -> None:
        assert InfraLayer.COMPUTE == "compute"
        assert len(InfraLayer) >= 3

    def test_drift_type(self) -> None:
        assert DriftType.UNAUTHORIZED == "unauthorized"
        assert len(DriftType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = InfrastructureDriftDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = InfrastructureDriftDetectorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"

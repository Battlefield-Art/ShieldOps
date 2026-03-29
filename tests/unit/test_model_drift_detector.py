"""Tests for model_drift_detector."""

from __future__ import annotations

from shieldops.agents.model_drift_detector.models import (
    DriftStage,
    DriftType,
    ModelDriftDetectorState,
    SeverityLevel,
)


class TestEnums:
    def test_driftstage(self) -> None:
        assert DriftStage.COLLECT == "collect"
        assert len(DriftStage) >= 3

    def test_drifttype(self) -> None:
        assert DriftType.DATA_DRIFT == "data_drift"
        assert len(DriftType) >= 3

    def test_severitylevel(self) -> None:
        assert SeverityLevel.CRITICAL == "critical"
        assert len(SeverityLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ModelDriftDetectorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ModelDriftDetectorState(run_id="x", tenant_id="t")
        assert s.run_id == "x"
